
; Make <TAB> in C mode just insert a tab if point is in the middle of a line
(setq c-tab-always-indent nil)

; Bind the key C-x g to goto-line
(global-set-key "\C-x\C-g" 'goto-line)

; Font lock mode
;(global-font-lock-mode t)

; Tag file Mozilla
(setq tags-table-list
      `("e:/code/alp/alp-20010105/src/core/src/org"))
;      `("c:/code/mkse/microsoft"))
;      `("c:/code/mkse/microsoft" "c:/code/alp/alp-20000524/src/alp"))
;      `("c:/code/alp/alp-20000524/src/alp"))

; Background color
;(set-background-color "linen")
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






