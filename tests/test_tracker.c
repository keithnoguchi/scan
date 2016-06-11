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

TEST(TrackerTest, CheckWrongRangePortBackToDefaultPorts)
{
	unsigned short expected_start = 1;
	unsigned short expected_end = UINT16_MAX;
	tracker_init(&tracker, 100, 99);
	LONGS_EQUAL(expected_start, tracker.start);
	LONGS_EQUAL(expected_end, tracker.end);
}

TEST(TrackerTest, CheckPortZeroStatus)
{
	const port_status_t expected = UNKNOWN;
	const unsigned short port = 0;
	LONGS_EQUAL(expected, tracker_status(&tracker, port));
}

TEST(TrackerTest, CheckPortOneStatus)
{
	const port_status_t expected = INIT;
	const unsigned port = 1;
	LONGS_EQUAL(expected, tracker_status(&tracker, port));
}

TEST(TrackerTest, CheckPort65535Status)
{
	const port_status_t expected = INIT;
	const unsigned port = 65535;
	LONGS_EQUAL(expected, tracker_status(&tracker, port));
}

TEST(TrackerTest, CheckPortOpenStatus)
{
	const port_status_t expected = OPEN;
	const unsigned short port = 65535;
	tracker_set_open(&tracker, port);
	LONGS_EQUAL(expected, tracker_status(&tracker, port));
}

TEST(TrackerTest, CheckPortClosedStatus)
{
	const port_status_t expected = CLOSED;
	const unsigned short port = 65535;
	tracker_set_closed(&tracker, port);
	LONGS_EQUAL(expected, tracker_status(&tracker, port));
}
