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
	static const unsigned short default_start_port = 1;
	static const unsigned short default_end_port = 65535;
	struct tracker tracker;

	void setup()
	{
		tracker_init(&tracker, default_start_port, default_end_port);
	}
	void teardown()
	{
		tracker_term(&tracker);
	}
};

TEST(TrackerTest, CheckPortZeroStatus)
{
	LONGS_EQUAL(tracker.status[0], UNKNOWN);
}

TEST(TrackerTest, CheckPortOneStatus)
{
	LONGS_EQUAL(tracker.status[1], INIT);
}

TEST(TrackerTest, CheckPort65535Statsu)
{
	LONGS_EQUAL(tracker.status[65535], INIT);
}
