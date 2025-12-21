#ImageStripper - this tool strips metadata from images - simple version
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
    gps_data = {}
    gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
    data = list(im.getdata())
    
    
    print("Filename: ", im.filename)
    print("Format: ", im.format)
    print("GPS IFD: ", gps_ifd)

    #EXIF
    if not exif:
        print("No EXIF data found.")
    else:
        
        for tag_id, value in exif.items():
            tag = ExifTags.TAGS.get(tag_id, tag_id)
            print(f"{tag}: {value}")
    #GPS       
    for key, val in gps_ifd.items():
        name = GPSTAGS.get(key, key)
        gps_data[name] = val

    #XMP
    try:
        xmp_data = im.getxmp()
    except Exception as e:
        print("XMP Parse error: ", e)
        
    if xmp_data:
        print("XMP (parsed):", xmp_data)
        print(xmp_data)
    elif 'xmp' in im.info:
        print("XMP (raw XML):")
        print(im.info['xmp'])
    else:
        print("No XMP found.")

    if 'xmp' in im.info:
        print(im.info['xmp'])
    print(gps_data)

    #Making a new image from only the images pixels
    clean = Image.new(im.mode, im.size)
    clean.putdata(data)
    clean.save("stripped.jpg")


    
input('Press ENTER to exit')
