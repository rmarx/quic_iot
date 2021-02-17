import os 
import sys

class Util:
    @staticmethod
    def check_dir(direc, description=""):
        errors = False
        if direc == "":
            direc = "."
        if not os.path.isdir(direc):
            errors = True
            if description == "":
                print("Error: The \"%s\" directory is missing." % (direc), file=sys.stderr)
            else:
                print("Error: %s \"%s\" is not a directory." % (description, direc), file=sys.stderr)
        else:
            if not os.access(direc, os.R_OK):
                errors = True
                print("Error: The directory \"%s\" does not have read permission." % (direc), file=sys.stderr)
            if not os.access(direc, os.X_OK):
                errors = True
                print("Error: The directory \"%s\" does not have execute permission." % (direc), file=sys.stderr)

        return errors