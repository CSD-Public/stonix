import os
import time
import shutil
from log_message import log_message

def make_valid_link(my_link, my_link_source, message_level="normal"):
    """ 
    Check if mylink exists, if it does, check if it is a link.
    If it isn't, move it and create a link.  Otherwise check
    if it's pointing to the right place. Move the link if it
    doesn't point to the right place.

    mylink: the link we want to make
    mylinksource: the place we want the link to point to

    @author: Roy Nielsen
    """
    success = False
    move_it = False
    create_new_link = False

    myDate = time.strftime("%C%y%m%d", time.localtime())
    myTime = time.strftime("%I%M%S%p", time.localtime())

    #####
    # create a name for a backup, if a backup is needed.
    # append the bak.date to the filename
    backup = my_link + "." + myDate + "." + myTime

    #####
    # Logic to determine what do if something already resides
    # in the link's path
    if not os.path.exists(my_link):
        create_new_link = True
    elif os.path.islink(my_link):
        # check if it is a valid link
        validLink = isvalidlink(my_link)
        # check if it is pointing where we want
        pointsTo = os.path.realpath(my_link) == os.path.abspath(my_link_source)

        if validLink and pointsTo:
            move_it = False
        else:
            move_it = True
    elif not os.path.exists(my_link):
        create_new_link = True
    elif os.path.isdir(my_link):
        move_it = True
    elif os.path.isfile(my_link):
        move_it = True
    else:
        log_message("Uknown error condition in postflight...", "normal", message_level)

    #####
    # Run the logic appropriate to the decision made above.
    if create_new_link:
        try:
            os.symlink(my_link_source, my_link)
            success = True
        except Exception, err:
            log_message("Exception trying to create link: " +
                        str(my_link) + " -> " + str(my_link_source))
            log_message("Associated exception: " + str(err))

    elif move_it:
        # move "mylink" to mylink.myDate.myTime
        try:
            shutil.move(my_link, backup)
        except Exception, err:
            log_message("Exception trying to move file: " + str(my_link))
            log_message("Associated exception: " + str(err))
        finally:
            try:
                os.symlink(my_link_source, my_link)
                success = True
            except Exception, err:
                log_message("Exception trying to create link: " +
                            str(my_link) + " -> " + str(my_link_source))
                log_message("Associated exception: " + str(err))
    else:
        log_message("Unknown error attempting to create link...", "normal", message_level)

    return success


if __name__ == '__main__':
    success = make_valid_link("./stonix.py", "/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix")

    if success:
        print "Yea!!"
    else:
        print "Damn it Jim!!!"

