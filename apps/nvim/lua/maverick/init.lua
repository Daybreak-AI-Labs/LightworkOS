-- maverick.nvim — drive the Lightwork agent runtime from Neovim.
--
-- A thin front end over the locally installed `maverick` CLI; nothing here
-- talks to a network itself.
--
--   :MaverickStart {goal}   start a goal (prompts when no arg)
--   :MaverickStatus         runtime status + cost (split)
--   :MaverickMonitor        live plan-tree TUI (terminal split)
--   :MaverickLogs           recent audit log entries
--   :MaverickHalt           arm the killswitch (confirms first)
--   :MaverickUnhalt         clear the killswitch
--
-- setup{} is optional:
--   require("maverick").setup({ cli = "/path/to/maverick", max_dollars = 5 })

local M = {}

M.config = {
  cli = "maverick",
  max_dollars = nil, -- when set, passed to `maverick start --max-dollars`
  control_timeout_ms = 30000,
}

function M.setup(opts)
  M.config = vim.tbl_deep_extend("force", M.config, opts or {})
end

local function term_run(args)
  vim.cmd("botright split")
  vim.cmd("resize 15")
  vim.fn.termopen(vim.list_extend({ M.config.cli }, args))
  vim.cmd("startinsert")
end

function M.start(goal)
  if goal == nil or goal == "" then
    vim.ui.input({ prompt = "Goal for Lightwork: " }, function(input)
      if input and input ~= "" then
        M.start(input)
      end
    end)
    return
  end
  local args = { "start", goal }
  if M.config.max_dollars then
    table.insert(args, "--max-dollars")
    table.insert(args, tostring(M.config.max_dollars))
  end
  term_run(args)
end

function M.status()
  term_run({ "status", "--cost" })
end

function M.monitor()
  term_run({ "monitor" })
end

function M.logs()
  term_run({ "logs" })
end

local control, generation = nil, 0

function M.cancel_control(silent)
  generation = generation + 1
  local prior = control
  control = nil
  if prior then
    if prior.timer then vim.fn.timer_stop(prior.timer) end
    if prior.job and prior.job > 0 then vim.fn.jobstop(prior.job) end
    if not silent then vim.notify("Local command supervision stopped; its outcome is unconfirmed. Check local state before retrying.", vim.log.levels.ERROR) end
  end
end

local function checked_halt(command, present)
  if control then
    vim.notify("A local control request is still running. Use :MaverickCancelControl to stop waiting, then inspect state.", vim.log.levels.ERROR)
    return
  end
  generation = generation + 1
  local mine, output, bytes = generation, "", 0
  local owner = {}
  control = owner
  vim.notify("Waiting for checked local halt state; :MaverickCancelControl stops supervision.", vim.log.levels.INFO)
  local function fail(message)
    if mine ~= generation or control ~= owner then return end
    M.cancel_control(true)
    vim.notify(message .. " Outcome unconfirmed; check local state before retrying.", vim.log.levels.ERROR)
  end
  local ok, job = pcall(vim.fn.jobstart, { M.config.cli, command, "--json" }, {
    stdout_buffered = false, stderr_buffered = false,
    on_stdout = function(_, data)
      if mine ~= generation or control ~= owner then return end
      local chunk = table.concat(data or {}, "\n")
      bytes = bytes + #chunk
      if bytes > 65536 then fail("The command response exceeded the supported size.") else output = output .. chunk end
    end,
    on_stderr = function(_, data)
      if mine ~= generation or control ~= owner then return end
      bytes = bytes + #table.concat(data or {}, "\n")
      if bytes > 65536 then fail("The command response exceeded the supported size.") end
    end,
    on_exit = function(_, status)
      if mine ~= generation or control ~= owner then return end
      if status ~= 0 then fail("The local command did not confirm success."); return end
      local parsed, result = pcall(vim.fn.json_decode, output)
      if not parsed or type(result) ~= "table" or result.command ~= command
        or result.acknowledged ~= true or result.scope ~= "local"
        or result.halt_file_present ~= present or result.work_stopped ~= false then
        fail("Local halt-file state was not confirmed."); return
      end
      if owner.timer then vim.fn.timer_stop(owner.timer) end
      control = nil
      vim.notify(present and "Local kill switch armed. Running work stops at its next checkpoint."
        or "Local kill switch cleared. Prior tasks were not restarted.", vim.log.levels.INFO)
    end,
  })
  if not ok or type(job) ~= "number" or job <= 0 then fail("The local command could not start."); return end
  owner.job = job
  if control == owner then
    owner.timer = vim.fn.timer_start(math.max(100, math.min(120000, tonumber(M.config.control_timeout_ms) or 30000)), function()
      fail("The local command exceeded its deadline.")
    end)
  end
end

function M.halt()
  vim.ui.select({ "No", "Yes — arm the local kill switch" },
    { prompt = "Arm the Lightwork killswitch?" },
    function(choice)
      if choice and choice:sub(1, 3) == "Yes" then
        checked_halt("halt", true)
      end
    end)
end

function M.unhalt()
  checked_halt("unhalt", false)
end

return M
