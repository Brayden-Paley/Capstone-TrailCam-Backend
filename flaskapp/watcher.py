from flaskapp.main import db
from flaskapp.tables import User, Image
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
from sqlalchemy.sql import text
import string

class Watcher:
    DIRECTORY_TO_WATCH = "."

    def __init__(self):
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print ("Error")

        self.observer.join()


class Handler(FileSystemEventHandler):

    @staticmethod
    def on_any_event(event):
        if event.is_directory:
            return None

        elif event.event_type == 'created':
            # Take any action here when a file is first created.
            print ("Received created event - %s." % event.src_path)
            #if anyone is more proficient in string editing be my guest
            #cause what I have here is pretty gross
            isPicture = "jpg" in event.src_path
            stringholder = string.ascii_letters + string.digits
            pos = next(i for i, x in enumerate(event.src_path) if x in stringholder)
            name = event.src_path[pos:]
            name = name.split(".")[0]
            str3 = '\'%s\''% name
            name = str3
            print(name)
            if(isPicture is True):
                exists = Image.query.filter_by(filename=text(name)).first()
                print(exists)
                if (not exists):
                    name = name.split("'")[1]
                    new_file = Image(filename=name, filepath=os.path.abspath(event.src_path), cameraID = '1')
                    db.session.add(new_file)
                    db.session.commit()
                    print(Image.query.all())

        elif event.event_type == 'closed':
            #itwould be better to do it on file closed instead of file created but
            #this feature was added literally this month and it doesn't seem to
            #work
            print ("Received closed event - %s." % event.src_path)


if __name__ == '__main__':
    w = Watcher()
    w.run()