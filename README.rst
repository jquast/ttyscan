| |pypi_downloads| |codecov| |windows| |linux| |mac| |bsd|

.. note:: This software is not yet released! It best integrates with the next release of
   Blessed (1.40), in review: https://github.com/jquast/blessed/pull/375

ttyscan
=======

*ttyscan* queries a terminal emulator for its type, size and capabilities, creating a
curses-compatible `terminfo(5)`_ file entry if necessary, and exports any corrected values of
``TERM``, ``COLORTERM``, ``LINES``, ``COLUMNS``, and optionally ``TERMCAP`` environment variables.

Installation
------------

.. code-block:: shell

   pip install ttyscan

*ttyscan* requires Python3.8+

Scope
-----

At time of this writing (May 2026), terminal capability transmission by ``XTGETTCAP`` is supported by
contour, foot_, ghostty_, iterm2_, kitty_, rio_, and wezterm_.  ``XTGETTCAP`` is the only protocol
capable of forwarding raw `terminfo(5)`_ capability strings.

Terminals that do not support ``XTGETTCAP`` include: alacritty, tmux, screen, Konsole, PuTTY,
rxvt-unicode, mintty, xterm.js, st, and Apple Terminal.  For these, ttyscan produces mostly no
output.

Problem
-------

ncurses_ does not support XTGETTCAP_, and so `terminfo(5)`_ files for some terminals **must** be
deployed by system operators to remote systems.  Curses programs fail to start remotely until a
database file is deployed, or an alternate ``TERM`` is exported, raising error::

       $ tmux attach
       missing or unsuitable terminal: xterm-kitty

       $ irssi
       setupterm() failed for TERM=xterm-kitty: 0
       Can't initialize screen handling.

       $ htop
       Error opening terminal: xterm-kitty.

       $ python -c 'import curses;curses.setupterm()'
       Traceback (most recent call last):
         File "<string>", line 1, in <module>
       _curses.error: setupterm: could not find terminal

Some workarounds include exporting a generally compatible ``TERM=xterm-256color``, ``vt220``, or
even ``ansi`` with some corruption of a small amount of screen output or keyboard input sequences.
For example, backspace and delete may not detect.

*ttyscan* acts as a compatibility layer, creating the missing `terminfo(5)` file using
XTGETTCAP_ when available, and exports ``TERMINFO`` so that legacy calls to curses
`setupterm(3)`_ succeed::

       $ ttyscan

       $ eval `ttyscan`

       $ echo $TERM, $TERMINFO
       xterm-kitty, /home/harlan/.config/ttyscan/terminfo

       $ file -b /home/harlan/.config/ttyscan/terminfo/x/xterm-kitty 
       Compiled terminfo entry "xterm-kitty"

       $ python -c 'import curses;curses.setupterm()'; echo $?
       0

TERM, Size and Colors
---------------------

``TERM``, ``COLORTERM``, ``LINES``, or ``COLUMNS`` may also not be transmitted by all clients,
accepted by all servers, or supported or forwarded by their protocols.  Some examples:

- ssh does not forward ``COLORTERM`` unless configured using ``SendEnv`` in `ssh_config(5)`_ and
  ``AcceptEnv`` in `sshd_config(5)`_.
- serial does not forward any; ``TERM`` is defined by host `agetty(8)`_ configuration, for example.
- rlogin can forward all but ``COLORTERM``.
- telnet can forward all, but IAC NAWS and NEW-ENVIRON capability varies by software.
- websocket cannot forward any without customization, often used in-browser.

*ttyscan* detects when these variables are unset or do not match the values detected using
XTGETTCAP_, and DEC Private Mode 2048 In-Band Resize Notification, and re-exports them.

Details
-------

The use of ``XTGETTCAP`` is best described by foot_:

  ``XTGETTCAP`` is an escape sequence initially introduced by XTerm, and also implemented (and extended,
  to some degree) by Kitty.
 
  Applications using this feature do not need to use the classic, file-based, terminfo definition.
 
  XTerm's implementation (as of XTerm-370) only supports querying key (as in keyboard keys)
  capabilities, and three custom capabilities:
  
  ``TN`` - terminal name
  ``Co`` - number of colors (alias for the colors capability)
  ``RGB`` - number of bits per color channel (different semantics from the RGB capability in file-based
  terminfo definitions!).
 
  Kitty has extended this, and also supports querying all integer and string capabilities.
 
  Foot supports this, and extends it even further, to also include boolean capabilities.
  **This means foot's entire terminfo can be queried via ``XTGETTCAP``.**

*ttyscan* uses the following,

- ``TN`` is used to correct ``TERM`` when unmatched.
- ``RGB`` is used to correct ``COLORTERM`` when unmatched.
- all capability strings, keyboard and screen, when provided by ``XTGETTCAP``.
- DEC Private Mode 2048 (In-Band Resize) to determine the window size
- Or failing that, Cursor Position Report like XTerm's `resize.c
  <https://github.com/joejulian/xterm/blob/master/resize.c>`_
- blessed_ library for all Terminal interaction and capability detection

Command-Line Arguments
======================

``-v, --verbose``
   Print diagnostic information to stderr.  Implies ``-f`` (unconditional
   export).  Useful to debug which capabilities are discovered.

``-f, --force``
   Force export of all values even when they are unchanged from the current
   environment.  Also forces re-installation of the terminfo entry.

``-t, --termcap``
   Also generate and export a ``TERMCAP`` entry alongside ``TERMINFO``.
   Termcap entries are compact, single-line records suitable for legacy
   termcap-only programs.

.. _`agetty(8)`: https://linux.die.net/man/8/agetty
.. _blessed: https://pypi.org/project/blessed/
.. _foot: https://codeberg.org/dnkl/foot#xtgettcap
.. _ncurses: https://invisible-island.net/ncurses/
.. _`setupterm(3)`: https://linux.die.net/man/3/setupterm
.. _`ssh_config(5)`: https://linux.die.net/man/5/ssh_config
.. _`sshd_config(5)`: https://linux.die.net/man/5/sshd_config
.. _`terminfo(5)`: https://linux.die.net/man/5/terminfo
.. _XTGETTCAP specification: https://gitlab.freedesktop.org/terminal-wg/specifications/-/merge_requests/7
.. |pypi_downloads| image:: https://img.shields.io/pypi/dm/ttyscan.svg?logo=pypi
    :alt: Downloads
    :target: https://pypi.org/project/ttyscan/
.. |codecov| image:: https://codecov.io/gh/jquast/ttyscan/branch/master/graph/badge.svg
    :alt: codecov.io Code Coverage
    :target: https://codecov.io/gh/jquast/ttyscan/
.. |linux| image:: https://img.shields.io/badge/Linux-yes-success?logo=linux
    :alt: Linux supported
.. |windows| image:: https://img.shields.io/badge/Windows-yes-success?logo=windows
    :alt: Windows supported
.. |mac| image:: https://img.shields.io/badge/MacOS-yes-success?logo=apple
    :alt: MacOS supported
.. |bsd| image:: https://img.shields.io/badge/BSD-yes-success?logo=freebsd
    :alt: BSD supported
