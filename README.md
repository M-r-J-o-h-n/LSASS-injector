# LSASS-injector
 

[ANNOUNCEMENT]
Some anti-cheat program now strip handle permission of lsass.
So to use this injector actaully , you need some modifications.

[HOW IT WORKS]
LSASS has a handle that has read and write permission to processes that need network connection.
This injector use that handle which noramlly is prohibited by some protection mechanism.

This solution contains two project.
One is manual map injector, and the other is manual map injector that runs in lsass.

Manual mapper map LsassInjector.dll.
Then LsassInjector map our dll to target process.
After injection is done, DedicatedInjector.exe erase every traces that it left.


