# ImageStripper (Metadata Removal Tool)

ImageStripper is a simple Python utility that removes metadata from image files by rebuilding the image using only its raw pixel data. The project is designed as a learning exercise to explore image formats, EXIF/GPS/XMP metadata, and how metadata persists across image saves.

The tool reads and displays available metadata (EXIF tags, GPS information, and XMP data when present), then creates a clean copy of the image without carrying over any embedded metadata.

**Features**

* Reads and displays EXIF metadata
* Extracts GPS metadata (when present)
* Attempts to parse XMP metadata (raw or structured)
* Rebuilds the image using only pixel data
* Outputs a metadata‑stripped image (stripped.jpg)
* Command‑line interface via argparse

**Technologies Used**

* Python 3
* Pillow (PIL)
* EXIF / GPS / XMP parsing

**Purpose**

Learning journey to explore:
* How image metadata is stored and accessed
* Differences between EXIF, GPS, and XMP metadata
* How to remove metadata safely by reconstructing image data
* Practical use of the Pillow imaging library

⚠️ Educational use only. This is a minimal implementation and does not handle all image formats, color profiles, or edge cases.
