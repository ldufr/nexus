Software to start multiple instances of Guild Wars (c).

The nexusdll.dll must be beside nexus.exe, but it doesn't need to be by the side
of Guild Wars. Nexus will work just fine if you already started Guild Wars, but
from a different installation. No Guild Wars instance should old a handle to the
Gw.dat that you will be using.

All processes started by nexus will have read access to the dat and will share
the read access as well. This avoid corruption of Gw.dat while still allowing
the client to read in it. For this reason, your Gw.dat should be completely
downloaded to not miss on textures or potentially not being able to load a map.
You can download *almost* everything by starting Guild Wars with the command
line arguments "-image". Item icons (and potentially other assets) are not
downloaded as part of "-image", so if you want to see them, you will need to
download them manually, by opening the installation manually and looking at the
item.

Finally, you start nexus with the command line:
```
nexus.exe "C:\Path\To\Gw\Gw.exe" -- <arguments forwarded to Gw.exe>
```

Arguments forwarded to Guild Wars are typically:
* -email "email@example.com"
* -password "mypassword"
* -character "My Character Name"
