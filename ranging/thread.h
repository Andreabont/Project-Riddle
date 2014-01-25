/* 
 * File:   thread.h
 * Author: andreabont
 *
 * Created on 25 gennaio 2014, 10.44
 */

#ifndef THREAD_H
#define	THREAD_H

#include <list>
#include <boost/thread/thread.hpp>
#include "tools.h"

extern boost::mutex mymutex;

/** The thread "printer" manages the display. */
void printer(std::list<device> *found, win_size winxy, int maxttl);

/** The thread "scribe" listens to incoming packets. */
void scribe(std::list<device> *found);

#endif	/* THREAD_H */

