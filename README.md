# Screenshot Ninja

Screenshot Ninja makes it easy to capture screenshots inside Binary Ninja.

## Features

Screenshot Ninja currently allows you to capture screenshots:

- of the active linear/graph view;
- of the entire Binary Ninja window; and
- at custom scaling factors, such as 2x or 3x the native resolution.

## Install

You can get Screenshot Ninja by:

- installing it through Binary Ninja's plugin manager;
- cloning this repository into your user plugins folder; or
- downloading and extracting a release into your user plugins folder.

If you plan to use the scripting functionality, the latter two options are
recommended, as the plugin manager adjusts module names.

## Usage

Screenshot Ninja can be used from the context menu or command palette, as well
as from the console as a Python module.

### From the user interface

Use the context menu or command palette to find Screenshot Ninja's commands. The
"save view image" command family will save an image of the active linear/graph
view, while the "save window image" command family will save an image of the
entire Binary Ninja window.

### As a Python module

You can import Screenshot Ninja in the Python console like this:

``` python
import screenshot_ninja
```

You can then use the `renderActiveView` and `renderActiveWindow` functions as
you wish. Both functions return a `QPixmap`, which you are responsible for
saving yourself. Additionally, both functions will throw a `ValueError` if
something goes wrong, so be sure to catch it.

## License

Copyright 2021-2023 Jon Palmisciano. Licensed under the MIT License. For
additional information, see [LICENSE.txt](LICENSE.txt).
