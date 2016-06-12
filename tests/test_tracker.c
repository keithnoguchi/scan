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

TEST_GROUP(Tracker)
{
	struct tracker tracker;

	void setup()
	{
		tracker_init(&tracker, 0, 0, NULL);
	}
	void teardown()
	{
		tracker_term(&tracker);
	}
};

TEST(Tracker, CheckDefaultStartPort)
{
	LONGS_EQUAL(1, tracker.begin);
}

TEST(Tracker, CheckDefaultEndPort)
{
	LONGS_EQUAL(UINT16_MAX, tracker.end);
}

TEST(Tracker, CheckDefaultNextPort)
{
	LONGS_EQUAL(1, tracker.next);
}

TEST(Tracker, CheckSpecifiedStartPort)
{
	unsigned short expected = 99;
	tracker_init(&tracker, expected, 0, NULL);
	LONGS_EQUAL(expected, tracker.begin);
}

TEST(Tracker, CheckSpecifiedEndPort)
{
	unsigned short expected = 100;
	tracker_init(&tracker, 0, expected, NULL);
	LONGS_EQUAL(expected, tracker.end);
}

TEST(Tracker, CheckWrongRangePortBackToDefaultPorts)
{
	unsigned short expected_begin = 1;
	unsigned short expected_end = UINT16_MAX;
	tracker_init(&tracker, 100, 99, NULL);
	LONGS_EQUAL(expected_begin, tracker.begin);
	LONGS_EQUAL(expected_end, tracker.end);
}

TEST(Tracker, CheckPortZeroStatus)
{
	const port_status_t expected = UNKNOWN;
	const unsigned short port = 0;
	LONGS_EQUAL(expected, tracker_status(&tracker, port));
}

TEST(Tracker, CheckPortOneStatus)
{
	const port_status_t expected = INIT;
	const unsigned port = 1;
	LONGS_EQUAL(expected, tracker_status(&tracker, port));
}

TEST(Tracker, CheckPort65535Status)
{
	const port_status_t expected = INIT;
	const unsigned port = 65535;
	LONGS_EQUAL(expected, tracker_status(&tracker, port));
}

TEST(Tracker, CheckPortOpenStatus)
{
	const port_status_t expected = OPEN;
	const unsigned short port = 65535;
	tracker_set_open(&tracker, port);
	LONGS_EQUAL(expected, tracker_status(&tracker, port));
}

TEST(Tracker, CheckPortClosedStatus)
{
	const port_status_t expected = CLOSED;
	const unsigned short port = 65535;
	tracker_set_closed(&tracker, port);
	LONGS_EQUAL(expected, tracker_status(&tracker, port));
}
