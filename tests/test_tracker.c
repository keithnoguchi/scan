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
		tracker_init(&tracker, 0, 0);
	}
	void teardown()
	{
		tracker_term(&tracker);
	}
};

TEST(TrackerTest, CheckDefaultStartPort)
{
	LONGS_EQUAL(1, tracker.start);
}

TEST(TrackerTest, CheckDefaultEndPort)
{
	LONGS_EQUAL(UINT16_MAX, tracker.end);
}

TEST(TrackerTest, CheckDefaultNextPort)
{
	LONGS_EQUAL(1, tracker.next);
}

TEST(TrackerTest, CheckSpecifiedStartPort)
{
	unsigned short expected = 99;
	tracker_init(&tracker, expected, 0);
	LONGS_EQUAL(expected, tracker.start);
}

TEST(TrackerTest, CheckSpecifiedEndPort)
{
	unsigned short expected = 100;
	tracker_init(&tracker, 0, expected);
	LONGS_EQUAL(expected, tracker.end);
}

TEST(TrackerTest, CheckPortZeroStatus)
{
	LONGS_EQUAL(UNKNOWN, tracker.status[0]);
}

TEST(TrackerTest, CheckPortOneStatus)
{
	LONGS_EQUAL(INIT, tracker.status[1]);
}

TEST(TrackerTest, CheckPort65535Status)
{
	LONGS_EQUAL(INIT, tracker.status[65535]);
}
