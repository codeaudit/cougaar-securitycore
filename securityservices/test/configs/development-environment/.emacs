;; Red Hat Linux default .emacs initialization file

;; Are we running XEmacs or Emacs?
(defvar running-xemacs (string-match "XEmacs\\|Lucid" emacs-version))

;; Set up the keyboard so the delete key on both the regular keyboard
;; and the keypad delete the character under the cursor and to the right
;; under X, instead of the default, backspace behavior.
(global-set-key [delete] 'delete-char)
(global-set-key [kp-delete] 'delete-char)

;; Turn on font-lock mode for Emacs
(cond ((not running-xemacs)
       (global-font-lock-mode t)
))

;; Always end a file with a newline
(setq require-final-newline t)

;; Stop at the end of the file, not just add lines
(setq next-line-add-newlines nil)

;; Enable wheelmouse support by default
(if (not running-xemacs)
    (require 'mwheel) ; Emacs
  (mwheel-install) ; XEmacs
)

;; ###################

; Make <TAB> in C mode just insert a tab if point is in the middle of a line
(setq c-tab-always-indent nil)

; Bind the key C-x g to goto-line
(global-set-key "\C-x\C-g" 'goto-line)

; Background color
(set-background-color "linen")

;
; Taken from Jeff Cook, 4/13/99 to run bash inside of emacs
;

;;; shell on WinNT to bash
(setenv "SHELL" "C:\\cygnus\\cygwin-b20\\H-i586-cygwin32\\bin\\bash.exe")
(setq shell-file-name
"C:\\cygnus\\cygwin-b20\\H-i586-cygwin32\\bin\\bash.exe")
(load "comint")
(fset 'original-comint-exec-1 (symbol-function 'comint-exec-1))
(defun comint-exec-1 (name buffer command switches)
  (let ((binary-process-input t)
	(binary-process-output nil))
    (original-comint-exec-1 name buffer command switches)))
(setq dired-chmod-program "chmod")
(setenv "PATH" (concat "C:\\cygnus\\cygwin-b20\\H-i586-cygwin32\\bin;"
		       (getenv "PATH")))
(setenv "COMSPEC" "C:\\cygnus\\cygwin-b20\\H-i586-cygwin32\\bin\\bash.exe")
(setq exec-path (cons "C:\\cygnus\\cygwin-b20\\H-i586-cygwin32\\bin"
exec-path))
;;; end of changes required for bash

