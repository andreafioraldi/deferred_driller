# deferred_driller
My version of driller using Intel PIN and angrgdb. In "theory" can work with AFL in deferred and persistent mode.

This is hugely based on the real [driller](https://github.com/shellphish/driller) so they deserve the majority of the credits.

What's new?

The tracer is based on a Pintool that forks from the deferred starting point and collects the trace of the children.
So no more aslr slides and avoiding to explore in angr the code before the deferred starting point may be an huge improvement when such code is complex.

## howto

Look at the example. All the files, also the Makefile.

This will not work on your code. Or at least can work with a low probability. This is a work in progress PoC of a bored student in the middle of the exams session.

### dependencies

All the following dependencies must be installed from the respective git repo and not from pip at the moment.

+ [archinfo](https://github.com/angr/archinfo)
+ [pyvex](https://github.com/angr/pyvex)
+ [ailment](https://github.com/angr/ailment)
+ [claripy](https://github.com/angr/claripy)
+ [cle](https://github.com/angr/cle)
+ [angr](https://github.com/angr/angr)

+ [angrdbg](https://github.com/andreafioraldi/angrdbg)
+ [angrgdb](https://github.com/andreafioraldi/angrgdb)



