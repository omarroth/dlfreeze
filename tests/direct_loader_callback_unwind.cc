#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <exception>
#include <link.h>
#include <pthread.h>
#include <stdexcept>

static int throw_from_callback(struct dl_phdr_info *, size_t, void *)
{
    throw std::runtime_error("from callback");
}

static void *lookup_from_another_thread(void *)
{
    return dlsym(RTLD_DEFAULT, "puts") ? nullptr
                                        : reinterpret_cast<void *>(1);
}

int main()
{
    // Some native libcs omit unwind information for dl_iterate_phdr. Give
    // that capability refusal a dedicated status, distinct from a crash.
    // The harness accepts it only from the unfrozen native control.
    std::set_terminate([] { std::_Exit(77); });
    try {
        (void)dl_iterate_phdr(throw_from_callback, nullptr);
    } catch (const std::exception &error) {
        pthread_t thread;
        void *thread_result = nullptr;

        if (pthread_create(&thread, nullptr, lookup_from_another_thread,
                           nullptr) != 0 ||
            pthread_join(thread, &thread_result) != 0 || thread_result)
            return 3;
        std::printf("caught:%s\n", error.what());
        return 0;
    }
    return 2;
}
