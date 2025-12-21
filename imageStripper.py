from PIL import Image
from PIL import ExifTags
from PIL.ExifTags import GPSTAGS
import argparse
import io

#args
def parse_args():
    parser = argparse.ArgumentParser(
        description="Strips metadata from images"
        )
    
    parser.add_argument(
        "file",
        type=str,
        help="File name"
        )

    return parser.parse_args()

args = parse_args()

with Image.open(args.file) as im:
    #im.show()
    exif = im.getexif()
    gpsData = {}
    gpsIFD = exif.get_ifd(ExifTags.IFD.GPSInfo)
    data = list(im.getdata())
    
    
    print("Filename: ", im.filename)
    print("Format: ", im.format)
    print("GPS IFD: ", gpsIFD)

    #EXIF
    if not exif:
        print("No EXIF data found.")
    else:
        
        for tagId, value in exif.items():
            tag = ExifTags.TAGS.get(tagId, tagId)
            print(f"{tag}: {value}")
    #GPS       
    for key, val in gpsIFD.items():
        name = GPSTAGS.get(key, key)
        gpsData[name] = val

    #XMP
    try:
        xmpData = im.getxmp()
    except Exception as e:
        print("XMP Parse error: ", e)
        
    if xmpData:
        print("XMP (parsed):", xmpData)
        print(xmpData)
    elif 'xmp' in im.info:
        print("XMP (raw XML):")
        print(im.info['xmp'])
    else:
        print("No XMP found.")

    if 'xmp' in im.info:
        print(im.info['xmp'])
    print(gpsData)

    
    clean = Image.new(im.mode, im.size)
    clean.putdata(data)
    clean.save("stripped.jpg")


    
input('Press ENTER to exit')
