/* 
 * File:   thread_printer.cpp
 * Author: andreabont
 *
 * Created on 25 gennaio 2014, 10.47
 */

#include <list>
#include <curses.h>
#include "thread.h"

using namespace std;

void printer(list<device> *found, win_size winxy, int maxttl) {

    static boost::posix_time::seconds delay(1);

    while (1) {

        boost::mutex::scoped_lock printer_lock(mymutex);

        clear();
        setHead(winxy);

        int countLine = 1;

        list<device>::iterator r = found->begin();

        while (r != found->end()) {

            if (time(NULL) > r->getEpoch() + maxttl) {

                list<device>::iterator ex = r;
                r++;
                found->erase(ex);

            } else {

                printLine(winxy, countLine, maxttl, r);
                r++;

            }

            countLine++;

        }

        printer_lock.unlock();

        boost::this_thread::sleep(delay);

    }

}
