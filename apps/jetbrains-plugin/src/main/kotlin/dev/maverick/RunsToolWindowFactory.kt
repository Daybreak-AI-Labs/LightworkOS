package dev.maverick

import com.intellij.openapi.Disposable
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.options.ShowSettingsUtil
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import java.net.URI
import java.net.URLEncoder
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JComboBox
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.Timer

/** Optional IDE scaffold: a single owned reader, bounded output, and cursor-based replay. */
class RunsToolWindowFactory : ToolWindowFactory {
    private data class GoalChoice(val id: Long, val title: String) {
        override fun toString() = "$title (task $id)"
    }
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val output = JBTextArea().apply { isEditable = false; accessibleContext.accessibleName = "Lightwork connection and task status" }
        output.document.addDocumentListener(object : javax.swing.event.DocumentListener {
            private fun changed() { output.accessibleContext.accessibleDescription = output.text.takeLast(500) }
            override fun insertUpdate(event: javax.swing.event.DocumentEvent) = changed()
            override fun removeUpdate(event: javax.swing.event.DocumentEvent) = changed()
            override fun changedUpdate(event: javax.swing.event.DocumentEvent) = changed()
        })
        val goalField = JTextField(8)
        val query = JTextField(18)
        val picker = JComboBox<GoalChoice>().apply { accessibleContext.accessibleName = "Authorized task matches" }
        val search = JButton("Find tasks")
        val configure = JButton("Settings")
        val test = JButton("Test connection")
        val connectionLabel = JLabel()
        val watch = JButton("Watch live")
        val stop = JButton("Stop")
        val disposed = AtomicBoolean(false)
        val generation = AtomicLong()
        val cursors = ConcurrentHashMap<String, Long>()
        var active: RunEventStream? = null
        var request: DashboardRequest? = null
        var pendingStart: (() -> Unit)? = null
        // Do not start a replacement until both the old reader and its closer have exited.
        val closing = Timer(100, null)
        closing.addActionListener {
            if (disposed.get()) { closing.stop(); return@addActionListener }
            if (active?.isAlive() != true) {
                closing.stop()
                active = null
                val next = pendingStart
                pendingStart = null
                next?.invoke()
            }
        }

        fun stopCurrent() {
            generation.incrementAndGet()
            pendingStart = null
            request?.close(); request = null
            active?.close()
            if (active?.isAlive() == true) closing.start()
        }

        fun clearConnection() {
            stopCurrent(); cursors.clear(); picker.removeAllItems(); goalField.text = ""; output.text = ""
            connectionLabel.text = "${DashboardSettings.name()} - ${DashboardSettings.base()}"
        }
        clearConnection()
        configure.addActionListener { ShowSettingsUtil.getInstance().showSettingsDialog(project, DashboardConfigurable::class.java) }
        fun readTasks(testOnly: Boolean) {
            stopCurrent()
            val mine = generation.get()
            picker.removeAllItems(); goalField.text = ""
            output.text = if (testOnly) "[Checking this connection.]\n" else "[Finding authorized tasks; up to 100 matches.]\n"
            val phrase = query.text.trim().take(200)
            val path = if (!testOnly && phrase.isNotEmpty()) "/api/v1/goals/search?limit=100&q=" + URLEncoder.encode(phrase, "UTF-8")
                else "/api/v1/goals?limit=${if (testOnly) 1 else 100}"
            request = DashboardRequest(DashboardSettings.base(), path) { result, error ->
                SwingUtilities.invokeLater {
                    if (!disposed.get() && !project.isDisposed && mine == generation.get()) {
                        output.text = when {
                            error != null -> "[$error]\n"
                            result?.isJsonArray != true -> "[Task list could not be verified. Check the dashboard version.]\n"
                            testOnly -> "[Connection confirmed for authorized task listing.]\n"
                            else -> {
                                result.asJsonArray.take(100).forEach { row ->
                                    try {
                                        val obj = row.asJsonObject; val id = obj.get("id").asLong
                                        val title = obj.get("title").asString.filter { !it.isISOControl() }.take(200)
                                        if (id > 0) picker.addItem(GoalChoice(id, title))
                                    } catch (_: Exception) { /* malformed rows never become a task target */ }
                                }
                                if (picker.itemCount == 0) "[No authorized matches. Try another title or check access in Settings.]\n"
                                else "[Choose a titled task, then Watch live. Search again for older tasks.]\n"
                            }
                        }
                    }
                }
            }.also { it.start() }
        }
        test.addActionListener { readTasks(true) }; search.addActionListener { readTasks(false) }
        watch.addActionListener {
            val goalId = if (goalField.text.isBlank()) (picker.selectedItem as? GoalChoice)?.id
                else goalField.text.trim().toLongOrNull()?.takeIf { it > 0 }
            if (goalId == null) {
                output.text = "[Choose a titled task with Find tasks, or enter a positive numeric task ID.]\n"
                goalField.accessibleContext.accessibleDescription = "Invalid selection. Choose a titled task with Find tasks or enter a positive numeric task ID."
                goalField.requestFocusInWindow()
                return@addActionListener
            }
            goalField.accessibleContext.accessibleDescription = "Optional positive numeric task ID; otherwise use the authorized task picker."
            stopCurrent()
            val mine = generation.get()
            val base = DashboardSettings.base()
            output.text = "[Opening task $goalId on ${DashboardSettings.name()} - $base.]\n"
            ApplicationManager.getApplication().executeOnPooledThread {
                val token = try { DashboardSettings.token(base) } catch (_: Exception) {
                    SwingUtilities.invokeLater { if (mine == generation.get() && !disposed.get()) output.text = "[Protected credentials unavailable. Repair IDE Passwords settings.]\n" }
                    return@executeOnPooledThread
                }
                SwingUtilities.invokeLater open@{
                    if (disposed.get() || mine != generation.get()) return@open
                    val uri = try { URI(DashboardSettings.validate(base, !token.isNullOrEmpty()) + "/api/v1/goals/$goalId/events/stream") }
                        catch (_: Exception) { output.text = "[Use HTTPS for remote tokens, or loopback HTTP. Repair the address in Settings.]\n"; return@open }
                    val key = MessageDigest.getInstance("SHA-256").digest((uri.toString() + "\u0000" + token.orEmpty()).toByteArray())
                        .joinToString("") { "%02x".format(it) }
                    if (!cursors.containsKey(key) && cursors.size >= 16) cursors.remove(cursors.keys.first())
                    val start: () -> Unit = start@{
                        if (disposed.get() || mine != generation.get()) return@start
                        val cursor = cursors[key] ?: 0L
                        if (cursor > 0) output.append("[Resuming after event $cursor; see the dashboard for earlier history.]\n")
                        active = RunEventStream(uri, token, cursor, emit = { line ->
                            var accepted = false
                            // Synchronous UI handoff bounds queued work and advances cursor only after display.
                            SwingUtilities.invokeAndWait {
                                if (!disposed.get() && !project.isDisposed && mine == generation.get()) {
                                    if (line.startsWith("[Stream refused: HTTP 401") || line.startsWith("[Stream refused: HTTP 403") || line.startsWith("[Run visibility changed")) {
                                        output.text = ""; cursors.remove(key); picker.removeAllItems(); goalField.text = ""
                                    }
                                    if (output.document.length + line.length > 1_000_000) {
                                        output.text = "[Earlier output cleared; see the dashboard for full history.]\n"
                                    }
                                    output.append(line + "\n")
                                    accepted = true
                                }
                            }
                            accepted
                        }, saveCursor = { cursorValue ->
                            if (!disposed.get() && mine == generation.get()) cursors[key] = cursorValue
                        }).also { it.start() }
                    }
                    if (active?.isAlive() == true) {
                        output.append("[Closing the previous watch before opening this run.]\n")
                        pendingStart = start
                        closing.start()
                    } else { active = null; start() }
                }
            }
        }
        stop.addActionListener { stopCurrent(); output.append("[Live watch stopped.]\n") }
        val controls = JPanel().apply {
            layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
            add(JPanel().apply { add(connectionLabel); add(configure); add(test) })
            add(JPanel().apply { add(JLabel("Task title search").apply { labelFor = query }); add(query); add(search); add(picker) })
            add(JPanel().apply { add(JLabel("Task ID (optional)").apply { labelFor = goalField }); add(goalField); add(watch); add(stop) })
        }
        val panel = JPanel(java.awt.BorderLayout()).apply {
            add(controls, java.awt.BorderLayout.NORTH)
            add(JBScrollPane(output), java.awt.BorderLayout.CENTER)
        }
        val content = toolWindow.contentManager.factory.createContent(panel, "", false)
        val owner = Disposable {
            disposed.set(true)
            stopCurrent()
            closing.stop()
            cursors.clear()
        }
        ApplicationManager.getApplication().messageBus.connect(owner).subscribe(DashboardSettings.TOPIC, object : DashboardSettings.Listener {
            override fun changed() { clearConnection() }
        })
        content.setDisposer(owner)
        toolWindow.contentManager.addContent(content)
    }
}
