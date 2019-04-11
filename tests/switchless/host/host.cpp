// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <limits>
#include <thread>
#include <vector>
#include "../../../host/sgx/enclave.h"

#include <time.h>
#include <climits>
#include <cstdlib>

#include "switchless_u.h"

static const size_t SAMPLE_SIZE = 1000;

struct test_data
{
    int arg1, arg2, sum;
    struct timespec start, stop;
};

void generate_test_data(test_data* begin_pos, test_data* end_pos)
{
    for (test_data* pos = begin_pos; pos != end_pos; ++pos)
    {
        pos->arg1 = rand() % (INT_MAX / 2);
        pos->arg2 = rand() % (INT_MAX / 2);
    }
}

bool operator<(timespec const& lhs, timespec const& rhs)
{
    return lhs.tv_sec < rhs.tv_sec ||
           (lhs.tv_sec == rhs.tv_sec && lhs.tv_nsec < rhs.tv_nsec);
}

bool operator<=(timespec const& lhs, timespec const& rhs)
{
    return lhs.tv_sec < rhs.tv_sec ||
           (lhs.tv_sec == rhs.tv_sec && lhs.tv_nsec <= rhs.tv_nsec);
}

timespec operator-(timespec const& lhs, timespec const& rhs)
{
    OE_TEST(!(lhs <= rhs));
    timespec out = {0, 0};
    if (rhs.tv_nsec > lhs.tv_nsec)
    {
        out.tv_sec = lhs.tv_sec - rhs.tv_sec - 1;
        out.tv_nsec = 1000000000 + lhs.tv_nsec - rhs.tv_nsec;
    }
    else
    {
        out.tv_sec = lhs.tv_sec - rhs.tv_sec;
        out.tv_nsec = lhs.tv_nsec - rhs.tv_nsec;
    }
    return out;
}

timespec operator+(timespec const& lhs, timespec const& rhs)
{
    timespec out = {0, 0};
    out.tv_sec = lhs.tv_sec + rhs.tv_sec;
    out.tv_nsec = lhs.tv_nsec + rhs.tv_nsec;
    while (1000000000 <= out.tv_nsec)
    {
        ++(out.tv_sec);
        (out.tv_nsec) -= 1000000000;
    }
    return out;
}

void analyze_data(test_data* begin_pos, test_data* end_pos)
{
    printf("  <analyze_data>\n");
    int count = 0;
    int correct = 0;
    timespec total_time = {0, 0};
    timespec shortest_time = {INT_MAX, INT_MAX};
    timespec longest_time = {0, 0};
    for (test_data* pos = begin_pos; pos != end_pos; ++pos)
    {
        ++count;
        if (pos->sum == (pos->arg1 + pos->arg2))
        {
            ++correct;
        }

        // printf(
        //     "    pos->start (sec): %.8f\n",
        //     static_cast<float>(pos->start.tv_sec) +
        //         static_cast<float>(pos->start.tv_nsec) / 1000000000.0f);
        // printf(
        //     "    pos->stop (sec): %.8f\n",
        //     static_cast<float>(pos->stop.tv_sec) +
        //         static_cast<float>(pos->stop.tv_nsec) / 1000000000.0f);

        timespec delta = pos->stop - pos->start;
        total_time = total_time + delta;
        if (delta < shortest_time)
        {
            shortest_time = delta;
        }
        if (longest_time < delta)
        {
            longest_time = delta;
        }
    }
    printf("    count: %d\n", count);
    printf(
        "    correct: %d/%d (%.1f%%)\n",
        correct,
        count,
        static_cast<float>(correct * 100) / static_cast<float>(count));
    printf(
        "    total_time (sec): %.8f\n",
        static_cast<float>(total_time.tv_sec) +
            static_cast<float>(total_time.tv_nsec) / 1000000000.0f);
    printf(
        "    shortest_time (sec): %.8f\n",
        static_cast<float>(shortest_time.tv_sec) +
            static_cast<float>(shortest_time.tv_nsec) / 1000000000.0f);
    printf(
        "    longest_time (sec): %.8f\n",
        static_cast<float>(longest_time.tv_sec) +
            static_cast<float>(longest_time.tv_nsec) / 1000000000.0f);
    printf(
        "    average_time (sec): %.8f\n",
        (static_cast<float>(total_time.tv_sec) +
         static_cast<float>(total_time.tv_nsec) / 1000000000.0f) /
            static_cast<float>(count));
    printf("  </analyze_data>\n");
}

oe_result_t test_standard_enc_sum(oe_enclave_t* enclave)
{
    oe_result_t result = OE_OK;
    test_data data[SAMPLE_SIZE];

    generate_test_data(data, data + SAMPLE_SIZE);
    printf("<test_standard_enc_sum>\n");
    for (test_data *pos = data, *end_pos = data + SAMPLE_SIZE;
         OE_OK == result && pos != end_pos;
         ++pos)
    {
        clock_gettime(CLOCK_REALTIME, &(pos->start));
        result = standard_enc_sum(enclave, &(pos->sum), pos->arg1, pos->arg2);
        if (OE_OK != result)
        {
            printf("  FAILED: %s\n", oe_result_str(result));
        }
        clock_gettime(CLOCK_REALTIME, &(pos->stop));
    }
    analyze_data(data, data + SAMPLE_SIZE);
    printf("</test_standard_enc_sum>\n");
    return result;
}

void test_single_thread_enc_queue()
{
    const size_t COUNT = 100;
    thread_control tc;
    init_thread_control(&tc, TC_RUNNING, 0x06FFFFFF);

    OE_TEST(nullptr == tc_pop_enc_queue(&tc));
    OE_TEST(nullptr == tc_pop_host_queue(&tc));

    tc_queue_node nodes[COUNT];
    for (tc_queue_node* pnode = nodes; pnode != nodes + COUNT; ++pnode)
    {
        tc_push_enc_queue(&tc, pnode);
    }
    for (size_t i = 0; i < COUNT; ++i)
    {
        tc_queue_node* pnode = tc_pop_enc_queue(&tc);
        OE_TEST(nodes + i == pnode);
    }

    for (tc_queue_node* pnode = nodes; pnode != nodes + COUNT; ++pnode)
    {
        tc_push_host_queue(&tc, pnode);
    }
    for (size_t i = 0; i < COUNT; ++i)
    {
        tc_queue_node* pnode = tc_pop_host_queue(&tc);
        OE_TEST(nodes + i == pnode);
    }

    OE_TEST(nullptr == tc_pop_enc_queue(&tc));
    OE_TEST(nullptr == tc_pop_host_queue(&tc));
}

void test_multi_thread_enc_queue_reader_thread(
    thread_control* ptc,
    tc_queue_node* pnodes,
    size_t count)
{
    // printf("  <test_multi_thread_enc_queue_reader_thread>\n");
    std::unique_ptr<size_t[]> counters(new size_t[count]);
    std::fill(counters.get(), counters.get() + count, 0);

    // pop all of the nodes
    for (size_t i = 0; i < count; ++i)
    {
        tc_queue_node* pnode = nullptr;
        do
        {
            pnode = tc_pop_enc_queue(ptc);
        } while (nullptr == pnode);
        size_t index = static_cast<size_t>(std::distance(pnodes, pnode));
        OE_TEST(index < count);
        ++counters[index];
    }

    // test that each node was popped exactly once
    OE_TEST(
        count == static_cast<size_t>(
                     std::count(counters.get(), counters.get() + count, 1)));

    // test that the queue is now empty
    OE_TEST(nullptr == tc_pop_enc_queue(ptc));
    // printf("  </test_multi_thread_enc_queue_reader_thread>\n");
}

void test_multi_thread_enc_queue_writer_thread(
    thread_control* ptc,
    tc_queue_node* pnodes,
    size_t count)
{
    // printf("  <test_multi_thread_enc_queue_writer_thread>\n");
    for (size_t i = 0; i < count; ++i)
    {
        tc_push_enc_queue(ptc, pnodes + i);
    }
    // printf("  </test_multi_thread_enc_queue_writer_thread>\n");
}

void test_multi_thread_enc_queue()
{
    // printf("<test_multi_thread_enc_queue>\n");
    const size_t NODE_COUNT = 100000;
    const size_t WRITER_THREAD_COUNT = 5;
    const size_t WRITER_NODE_COUNT = NODE_COUNT / WRITER_THREAD_COUNT;
    thread_control tc;
    init_thread_control(&tc, TC_RUNNING, 0x06FFFFFF);
    tc_queue_node nodes[NODE_COUNT];

    std::thread reader_thread = std::thread(
        test_multi_thread_enc_queue_reader_thread, &tc, nodes, NODE_COUNT);
    std::thread writer_threads[WRITER_THREAD_COUNT];
    for (size_t i = 0; i < WRITER_THREAD_COUNT; ++i)
    {
        writer_threads[i] = std::thread(
            test_multi_thread_enc_queue_writer_thread,
            &tc,
            nodes + i * WRITER_NODE_COUNT,
            WRITER_NODE_COUNT);
    }
    for (size_t i = 0; i < WRITER_THREAD_COUNT; ++i)
    {
        writer_threads[i].join();
    }
    reader_thread.join();
    // printf("</test_multi_thread_enc_queue>\n");
}

#if (__SWITCHLESS__)
void enc_worker_thread(oe_enclave_t* enclave, thread_control* ptc)
{
    oe_result_t result = switchless_enc_worker_thread(enclave, ptc);
    OE_TEST(OE_OK == result);
    // these next two lines are very likely to have race conditions in a
    // truly multi-threaded application when the ptc is restarted
    OE_TEST(TC_STOPPED == tc_get_state(ptc));
    tc_set_state(ptc, TC_EXITED);
}
#endif // __SWITCHLESS__

#if (__SWITCHLESS__)
void test_switchless_infrastructure(oe_enclave_t* enclave)
#else  // __SWITCHLESS__
void test_switchless_infrastructure()
#endif // __SWITCHLESS__
{
    // test that the queues work
    test_single_thread_enc_queue();
    test_multi_thread_enc_queue();

#if (__SWITCHLESS__)
    thread_control tc;
    std::thread worker_thread;

    // test that the thread can be stopped
    init_thread_control(&tc, TC_RUNNING, std::numeric_limits<size_t>::max());
    worker_thread = std::thread(enc_worker_thread, enclave, &tc);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    OE_TEST(TC_RUNNING == tc_get_state(&tc));
    tc_set_state(&tc, TC_STOPPING);
    worker_thread.join();
    OE_TEST(TC_EXITED == tc_get_state(&tc));

    // test that the thread can exit after the count expires
    init_thread_control(&tc, TC_RUNNING, 0x06FFFFFF);
    worker_thread = std::thread(enc_worker_thread, enclave, &tc);
    worker_thread.join();
    OE_TEST(TC_EXITED == tc_get_state(&tc));
#endif // __SWITCHLESS__
}

oe_result_t test_synchronous_enc_sum(oe_enclave_t* enclave)
{
    oe_result_t result = OE_OK;
    test_data data[SAMPLE_SIZE];

    generate_test_data(data, data + SAMPLE_SIZE);
    printf("<test_synchronous_enc_sum>\n");

#if (__SWITCHLESS__)
    // start a worker thread
    thread_control tc;
    init_thread_control(&tc, TC_RUNNING, 0x06FFFFFFFF);
    std::thread worker_thread = std::thread(enc_worker_thread, enclave, &tc);
#endif // __SWITCHLESS__

    for (test_data *pos = data, *end_pos = data + SAMPLE_SIZE;
         OE_OK == result && pos != end_pos;
         ++pos)
    {
        clock_gettime(CLOCK_REALTIME, &(pos->start));

#if (__SWITCHLESS__)
        result = synchronous_switchless_enc_sum(
            &tc, &(pos->sum), pos->arg1, pos->arg2);
#else  // __SWITCHLESS__
        result = synchronous_switchless_enc_sum(
            enclave, &(pos->sum), pos->arg1, pos->arg2);
#endif // __SWITCHLESS__
        if (OE_OK != result)
        {
            printf("  FAILED: %s\n", oe_result_str(result));
        }

        clock_gettime(CLOCK_REALTIME, &(pos->stop));
    }
    analyze_data(data, data + SAMPLE_SIZE);

#if (__SWITCHLESS__)
    // kill the worker thread
    tc_set_state(&tc, TC_STOPPING);
    worker_thread.join();
    OE_TEST(TC_EXITED == tc_get_state(&tc));
#endif // __SWITCHLESS__

    printf("</test_synchronous_enc_sum>\n");
    return result;
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();
    oe_enclave_t* enclave = nullptr;
    oe_result_t result = oe_create_switchless_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
    {
        oe_put_err("oe_create_switchless_enclave(): result=%u", result);
    }

    // gather metrics for standard ecalls
    if (OE_OK != (result = test_standard_enc_sum(enclave)))
    {
        oe_put_err("test_standard_enc_sum: result=%u", result);
        OE_TEST(OE_OK == result && "test_standard_enc_sum");
    }

    // this is a valid unit test of the infrastructure but it takes time
    // test the switchless infrastructure
#if (__SWITCHLESS__)
    // test_switchless_infrastructure(enclave);
#else  // __SWITCHLESS__
    // test_switchless_infrastructure();
#endif // __SWITCHLESS__

    // gather metrics for synchronous ecalls
    if (OE_OK != (result = test_synchronous_enc_sum(enclave)))
    {
        oe_put_err("test_synchronous_enc_sum: result=%u", result);
        OE_TEST(OE_OK == result && "test_synchronous_enc_sum");
    }

    if (OE_OK != (result = oe_terminate_enclave(enclave)))
    {
        oe_put_err("oe_terminate_enclave: result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
