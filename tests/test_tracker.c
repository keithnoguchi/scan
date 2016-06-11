#include "CppUTest/TestHarness.h"

extern "C"
{
#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tracker.h"
}

TEST_GROUP(TrackerTest)
{
	struct tracker tracker;

	void setup()
	{
		tracker_init(&tracker);
	}
	void teardown()
	{
		tracker_term(&tracker);
	}
};

TEST(TrackerTest, CheckPortOneStatus)
{
	LONGS_EQUAL(tracker.status[1], UNKNOWN);
}
