// What an observation of a unit answers (SPEC.md clause 7.18, version 0.26).
//
// A unit here is a named job in the session's namespace, and its reference
// (`W2') names the count of boots and the session beside the job's name. Until
// 0.23.0 it named neither: a reference of an earlier boot and one of another
// session both failed to open as a name that is not there, which a caller
// could not tell from a condition that passes. The cases alter a real
// reference one field at a time, which is how a reference from elsewhere reads
// to this program.
#include <string>
#include <vector>
#include <openkal/process.h>
#include <openkal/types.h>
import mcpplibs.mtest;

using namespace mcpplibs::mtest;

namespace {

std::vector<std::string> fields(const std::string& r) {
    std::vector<std::string> out(1);
    for (char c : r) { if (c == ';') out.emplace_back(); else out.back() += c; }
    return out;
}
std::string joined(const std::vector<std::string>& f) {
    std::string out;
    for (std::size_t i = 0; i < f.size(); ++i) { if (i) out += ';'; out += f[i]; }
    return out;
}

// What `open' answers, and the state an observation gives where it opens.
struct answer { int open = 0; kal_u32 state = KAL_JOB_UNKNOWN; };
answer ask(const std::string& reference) {
    answer a; kal_job job{};
    a.open = kal_process_job_open(reference.data(), reference.size(), &job);
    if (a.open == kal_ok) {
        kal_process_job_observe(job, reference.data(), reference.size(), &a.state);
        kal_process_job_close(job);
    }
    return a;
}

}  // namespace

UTest a_unit_reference_names_its_boot_and_session_test{"a_unit_reference_names_its_boot_and_session", [] {
    expect(fatal((kal_process_props() & KAL_PROCESS_PROP_JOB_OBSERVE) != 0))
        << "this environment lets a reference be made, so observation is claimed";

    // This program declares the unit and is its member for the whole test.
    kal_job unit{}; char bytes[256]; kal_uintptr used = 0;
    expect(fatal(kal_process_job_create(&unit, bytes, sizeof bytes, &used) == kal_ok)) << "a unit is declared";
    const std::string reference(bytes, used);
    const auto f = fields(reference);
    expect(fatal(f.size() == 6 && f[0] == "W2")) << "the reference is `W2;owner;birth;name;boot;session': " << reference;

    {
        const auto a = ask(reference);
        expect(a.open == kal_ok && a.state == KAL_JOB_OCCUPIED)
            << "a unit with a running member is occupied (open " << a.open << ", state " << a.state << ")";
    }
    // Another boot: every program of it has ended. A system that keeps no count
    // of boots states none, and none is compared.
    if (f[4] != "0") {
        auto g = f; g[4] = std::to_string(std::stoull(f[4]) + 1);
        const auto a = ask(joined(g));
        expect(a.open == kal_ok && a.state == KAL_JOB_EMPTY)
            << "a reference of another boot is empty (open " << a.open << ", state " << a.state << ")";
    }
    {   // Another session: its names are not this session's.
        auto g = f; g[5] = std::to_string(std::stoull(f[5]) + 1);
        expect(ask(joined(g)).open == kal_err_not_supported) << "a reference of another session is not observable";
    }
    {   // A name the system no longer keeps: dropped with its last handle,
        // whether or not a member remained.
        auto g = f; char& last = g[3].back(); last = last == '0' ? '1' : '0';
        expect(ask(joined(g)).open == kal_err_not_supported) << "a unit whose name the system dropped is not observable";
    }
    {   // The earlier form names its unit by name alone and is answered by it.
        auto g = f; g[0] = "W1"; g.resize(4);
        const auto a = ask(joined(g));
        expect(a.open == kal_ok && a.state == KAL_JOB_OCCUPIED) << "a reference in the earlier form is answered by its name";
    }
    kal_process_job_close(unit);
}};
