-- Command registration for maverick.nvim (loaded automatically by Neovim).
if vim.g.loaded_maverick_nvim then
  return
end
vim.g.loaded_maverick_nvim = true

local function mv()
  return require("maverick")
end

vim.api.nvim_create_user_command("MaverickStart", function(opts)
  mv().start(opts.args)
end, { nargs = "?", desc = "Start a Lightwork goal" })

vim.api.nvim_create_user_command("MaverickStatus", function()
  mv().status()
end, { desc = "Lightwork runtime status + cost" })

vim.api.nvim_create_user_command("MaverickMonitor", function()
  mv().monitor()
end, { desc = "Live Lightwork plan-tree monitor" })

vim.api.nvim_create_user_command("MaverickLogs", function()
  mv().logs()
end, { desc = "Recent Lightwork audit log entries" })

vim.api.nvim_create_user_command("MaverickHalt", function()
  mv().halt()
end, { desc = "Arm the Lightwork killswitch" })

vim.api.nvim_create_user_command("MaverickUnhalt", function()
  mv().unhalt()
end, { desc = "Clear the Lightwork killswitch" })

vim.api.nvim_create_user_command("MaverickCancelControl", function()
  mv().cancel_control()
end, { desc = "Stop waiting for a local command; outcome remains unconfirmed" })

vim.api.nvim_create_autocmd("VimLeavePre", {
  callback = function() mv().cancel_control(true) end,
})
