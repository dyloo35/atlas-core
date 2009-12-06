# Notice

*Out of character.*

This repository is part of an alternate reality game. The README is
intentional. The program is not a trick.

`atlascore.py` opens one listening socket on 127.0.0.1, reads the file next to
it, answers questions on that socket, and exits when you stop it. It makes no
outbound connection, writes nothing to disk, spawns nothing and installs
nothing. It has no dependencies beyond the Python standard library.

    python3 atlascore.py

It is one short file. Read it before you run it — you should not take that
sentence from a stranger's repository on faith, which is rather the point.

To remove it, delete the folder.
