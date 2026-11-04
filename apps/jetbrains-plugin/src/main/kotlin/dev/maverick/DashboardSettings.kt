package dev.maverick

import com.intellij.credentialStore.CredentialAttributes
import com.intellij.credentialStore.generateServiceName
import com.intellij.ide.passwordSafe.PasswordSafe
import com.intellij.ide.util.PropertiesComponent
import com.intellij.openapi.options.ConfigurationException
import com.intellij.openapi.options.SearchableConfigurable
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.application.ApplicationManager
import com.intellij.util.messages.Topic
import java.net.URI
import java.util.concurrent.atomic.AtomicReference
import javax.swing.*

/** Only the address/name live in ordinary settings; PasswordSafe owns credentials. */
internal object DashboardSettings {
    interface Listener { fun changed() }
    val TOPIC = Topic.create("Lightwork connection changed", Listener::class.java)
    private val properties get() = PropertiesComponent.getInstance()
    fun base(): String = properties.getValue("lightwork.dashboard.base", System.getenv("MAVERICK_DASHBOARD_URL")?.trimEnd('/') ?: "http://127.0.0.1:8765")
    fun name(): String = properties.getValue("lightwork.dashboard.name", "My dashboard")
    private fun attributes(base: String) = CredentialAttributes(generateServiceName("Lightwork dashboard", base))
    fun token(endpoint: String): String? = PasswordSafe.instance.getPassword(attributes(endpoint))
        ?: if (!properties.getBoolean("lightwork.dashboard.configured", false) && endpoint == base()) System.getenv("MAVERICK_DASHBOARD_TOKEN") else null
    fun validate(raw: String, authenticated: Boolean): String {
        val uri = URI(raw.trim().trimEnd('/'))
        require(RunEventStream.validEndpoint(uri) && uri.query == null && uri.fragment == null) {
            "Use a dashboard HTTP(S) base address without credentials, a query or a fragment."
        }
        require(!authenticated || RunEventStream.tokenTransportSafe(uri)) {
            "A remote access token requires HTTPS; HTTP is allowed only on loopback."
        }
        return uri.toString()
    }
    // Called in a modal background task, never on the event dispatch thread.
    fun save(name: String, raw: String, replacement: String?, disconnect: Boolean) {
        val base = validate(raw, !replacement.isNullOrEmpty())
        val token = if (disconnect) null else replacement ?: token(base)
        validate(base, !token.isNullOrEmpty())
        PasswordSafe.instance.setPassword(attributes(base), token)
        check(PasswordSafe.instance.getPassword(attributes(base)).orEmpty() == token.orEmpty()) {
            "Protected credential storage did not confirm the save. Existing address settings were retained."
        }
        properties.setValue("lightwork.dashboard.configured", true)
        properties.setValue("lightwork.dashboard.base", base)
        properties.setValue("lightwork.dashboard.name", name.trim().take(100).ifEmpty { "My dashboard" })
    }
    fun notifyChanged() = ApplicationManager.getApplication().messageBus.syncPublisher(TOPIC).changed()
}

/** Native Settings page; password reads/writes occur on a background thread. */
class DashboardConfigurable : SearchableConfigurable {
    private val name = JTextField(30)
    private val address = JTextField(40)
    private val password = JPasswordField(30)
    private val disconnect = JCheckBox("Remove the protected token for this address")
    private val status = JLabel("Save, then use Test connection in Lightwork Runs. Blank token keeps this address's saved token.")
    override fun getId() = "lightwork.dashboard"
    override fun getDisplayName() = "Lightwork Dashboard"
    override fun createComponent(): JComponent = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        fun field(label: String, component: JComponent) {
            add(JPanel(java.awt.FlowLayout(java.awt.FlowLayout.LEFT)).apply {
                add(JLabel(label).apply { labelFor = component }); add(component)
            })
        }
        field("Connection name", this@DashboardConfigurable.name); field("Dashboard address", address)
        field("Replace access token", password); add(disconnect); add(status)
    }
    override fun reset() { name.text = DashboardSettings.name(); address.text = DashboardSettings.base(); password.text = ""; disconnect.isSelected = false }
    override fun isModified() = name.text != DashboardSettings.name() || address.text != DashboardSettings.base() || password.password.isNotEmpty() || disconnect.isSelected
    override fun apply() {
        val newName = name.text; val newAddress = address.text
        val chars = password.password
        val replacement = if (chars.isEmpty()) null else String(chars)
        chars.fill('\u0000')
        try { DashboardSettings.validate(newAddress, !replacement.isNullOrEmpty()) }
        catch (_: Exception) { throw ConfigurationException("Use HTTPS for a remote token, or HTTP on loopback, without embedded credentials or URL query/fragment.") }
        val failure = AtomicReference<Exception?>(null)
        val remove = disconnect.isSelected
        ProgressManager.getInstance().run(object : Task.Modal(null, "Save Lightwork connection", false) {
            override fun run(indicator: ProgressIndicator) {
                try { DashboardSettings.save(newName, newAddress, replacement, remove) }
                catch (error: Exception) { failure.set(error) }
            }
        })
        DashboardSettings.notifyChanged() // Invalidate old views even if a partial credential save is uncertain.
        if (failure.get() != null) throw ConfigurationException("Protected connection save was not confirmed. Previous address settings remain; repair IDE Passwords settings and retry deliberately.")
        reset()
    }
    override fun disposeUIResources() { password.text = "" }
}
