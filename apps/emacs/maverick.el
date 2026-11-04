;;; maverick.el --- Drive the Lightwork agent runtime from Emacs -*- lexical-binding: t; -*-

;; Copyright (C) 2026 Christopher Day
;; SPDX-License-Identifier: Apache-2.0

;; Author: The Lightwork Authors
;; Version: 0.1.0
;; Package-Requires: ((emacs "27.1"))
;; Keywords: tools, processes
;; URL: https://github.com/Daybreak-AI-Labs/LightworkOS

;;; Commentary:

;; A thin, dependency-free front end over the `maverick' CLI:
;;
;;   M-x maverick-start    — prompt for a goal, run it (async, compilation buffer)
;;   M-x maverick-status   — show runtime status (+ cost)
;;   M-x maverick-monitor  — live plan-tree TUI in a term buffer
;;   M-x maverick-logs     — tail recent run logs
;;   M-x maverick-halt     — arm the killswitch (~/.maverick/HALT)
;;   M-x maverick-unhalt   — clear the killswitch
;;
;; The package shells out to the locally installed CLI; nothing here talks to
;; a network itself.  Set `maverick-cli-path' if `maverick' isn't on PATH.

;;; Code:

(require 'json)
(require 'cl-lib)

(defgroup maverick nil
  "Drive the Lightwork agent runtime."
  :group 'tools
  :prefix "maverick-")

(defcustom maverick-cli-path "maverick"
  "Path to the maverick CLI executable."
  :type 'string
  :group 'maverick)

(defcustom maverick-default-max-dollars nil
  "When non-nil, pass --max-dollars to `maverick start'."
  :type '(choice (const :tag "Use config default" nil) number)
  :group 'maverick)

(defcustom maverick-control-timeout 30
  "Seconds to supervise a status or halt command before marking it unconfirmed."
  :type 'number
  :group 'maverick)

(defvar maverick--requests (make-hash-table :test 'equal))

(defun maverick--async (channel args callback)
  "Own one bounded nonblocking CLI command for CHANNEL, ARGS and CALLBACK."
  (let ((previous (gethash channel maverick--requests)))
    (when (and previous (process-live-p previous))
      (user-error "A Lightwork control is running; use maverick-cancel-control, then inspect state")))
  (let (proc timer finished (text "") (size 0))
    (cl-labels
        ((finish (ok reason)
           (unless finished
             (setq finished t)
             (when timer (cancel-timer timer))
             (when (and proc (process-live-p proc)) (delete-process proc))
             (when (eq (gethash channel maverick--requests) proc)
               (remhash channel maverick--requests)
               (funcall callback ok (if ok text reason))))))
      (condition-case nil
          (progn
            (setq proc
                  (make-process
                   :name (concat "lightwork-" channel) :buffer nil :noquery t
                   :command (cons maverick-cli-path args) :connection-type 'pipe
                   :filter (lambda (_process chunk)
                             (unless finished
                               (setq size (+ size (string-bytes chunk)))
                               (if (> size 65536)
                                   (finish nil "Response exceeded its size limit; outcome unconfirmed")
                                 (setq text (concat text chunk)))))
                   :sentinel (lambda (process _event)
                               (when (memq (process-status process) '(exit signal failed))
                                 (finish (and (eq (process-status process) 'exit)
                                              (zerop (process-exit-status process)))
                                         "Command did not confirm success; outcome unconfirmed")))))
            (puthash channel proc maverick--requests)
            (process-put proc 'lightwork-cancel
                         (lambda () (finish nil "Local supervision cancelled; effect outcome unconfirmed")))
            (setq timer (run-at-time (max 0.1 (min 120 maverick-control-timeout)) nil
                                     (lambda () (finish nil "Command deadline exceeded; outcome unconfirmed")))))
        (error
         (when timer (cancel-timer timer))
         (when (and proc (process-live-p proc)) (delete-process proc))
         (remhash channel maverick--requests)
         (funcall callback nil "Local command could not start; outcome unconfirmed"))))))

;;;###autoload
(defun maverick-cancel-control ()
  "Stop local command supervision; this does not undo an external effect."
  (interactive)
  (let (owners)
    (maphash (lambda (_key process) (push process owners)) maverick--requests)
    (dolist (process owners)
      (let ((cancel (process-get process 'lightwork-cancel)))
        (when cancel (funcall cancel))))))

(add-hook 'kill-emacs-hook #'maverick-cancel-control)

(defun maverick--command (&rest args)
  "Build a shell command string from `maverick-cli-path' and ARGS."
  (mapconcat #'shell-quote-argument
             (cons maverick-cli-path (delq nil args))
             " "))

;;;###autoload
(defun maverick-start (goal)
  "Start the Lightwork swarm on GOAL (asynchronously)."
  (interactive "sGoal for Lightwork: ")
  (let ((cmd (if maverick-default-max-dollars
                 (maverick--command "start" goal "--max-dollars"
                                    (number-to-string maverick-default-max-dollars))
               (maverick--command "start" goal))))
    (compilation-start cmd nil (lambda (_) "*maverick-run*"))))

;;;###autoload
(defun maverick-status ()
  "Show Lightwork runtime status without blocking the editor."
  (interactive)
  (let ((buf (get-buffer-create "*maverick-status*")))
    (with-current-buffer buf
      (let ((inhibit-read-only t))
        (erase-buffer)
        (insert "Loading local status. M-x maverick-cancel-control stops waiting.\n"))
      (special-mode))
    (pop-to-buffer buf)
    (maverick--async
     "status" '("status" "--cost")
     (lambda (ok text)
       (when (buffer-live-p buf)
         (with-current-buffer buf
           (let ((inhibit-read-only t))
             (erase-buffer)
             (insert (if ok text (concat text ". Inspect local state before retrying.\n"))))))))))

;;;###autoload
(defun maverick-monitor ()
  "Open the live plan-tree monitor in a term buffer."
  (interactive)
  (require 'term)
  (let ((buf (term-ansi-make-term "*maverick-monitor*" maverick-cli-path nil "monitor")))
    (with-current-buffer buf (term-char-mode))
    (pop-to-buffer buf)))

;;;###autoload
(defun maverick-logs ()
  "Show recent Lightwork run logs."
  (interactive)
  (compilation-start (maverick--command "logs") nil (lambda (_) "*maverick-logs*")))

;;;###autoload
(defun maverick-halt ()
  "Arm the local Lightwork killswitch for upcoming execution checkpoints."
  (interactive)
  (when (yes-or-no-p "Arm the local killswitch? Running work stops at its next checkpoint. ")
    (maverick--checked-halt "halt" t)))

(defun maverick--checked-halt (command present)
  "Asynchronously run COMMAND and validate local halt-file state PRESENT."
  (message "Waiting for checked local halt state; M-x maverick-cancel-control stops supervision")
  (maverick--async
   "halt-control" (list command "--json")
   (lambda (ok text)
     (condition-case nil
         (progn
           (unless ok (error "Unconfirmed"))
           (let* ((json-object-type 'alist) (json-key-type 'symbol) (json-false :false)
                  (result (json-read-from-string text)))
             (unless (and (equal (alist-get 'command result) command)
                          (eq (alist-get 'acknowledged result) t)
                          (equal (alist-get 'scope result) "local")
                          (eq (alist-get 'halt_file_present result) (if present t :false))
                          (eq (alist-get 'work_stopped result) :false))
               (error "Unconfirmed"))
             (message "%s" (if present
                 "Local kill switch armed. Running work stops at its next checkpoint."
               "Local kill switch cleared. Prior tasks were not restarted."))))
       (error (message "Lightwork outcome unconfirmed. Check local state before retrying; external work may already have occurred."))))))

;;;###autoload
(defun maverick-unhalt ()
  "Clear the Lightwork killswitch."
  (interactive)
  (maverick--checked-halt "unhalt" nil))

(provide 'maverick)

;;; maverick.el ends here
