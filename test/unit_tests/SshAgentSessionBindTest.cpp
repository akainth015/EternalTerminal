#ifndef WIN32
#include <poll.h>
#endif

#include <future>

#include "PipeSocketHandler.hpp"
#include "PortForwardHandler.hpp"
#include "SshAgentSessionBind.hpp"
#include "SshSetupHandler.hpp"
#include "TcpSocketHandler.hpp"
#include "TestHeaders.hpp"

using namespace et;

namespace {
constexpr char SSH_AGENT_FAILURE = 5;
constexpr char SSH_AGENT_SUCCESS = 6;
constexpr char SSH_AGENTC_REQUEST_IDENTITIES = 11;
constexpr char SSH_AGENT_IDENTITIES_ANSWER = 12;

string u32(uint32_t v) {
  return {char(v >> 24), char(v >> 16), char(v >> 8), char(v)};
}

string sshString(const string& s) { return u32(s.size()) + s; }

string sessionBind(const string& hostKey, bool forwarding) {
  return string(1, char(27)) + sshString("session-bind@openssh.com") +
         sshString(hostKey) + sshString("session-id-" + hostKey) +
         sshString("signature-" + hostKey) + string(1, char(forwarding));
}

string frame(const string& body) { return u32(body.size()) + body; }

#ifndef WIN32
bool writeAll(int fd, const string& data) {
  size_t pos = 0;
  while (pos < data.size()) {
    ssize_t n = ::send(fd, data.data() + pos, data.size() - pos, MSG_NOSIGNAL);
    if (n <= 0) {
      return false;
    }
    pos += n;
  }
  return true;
}

bool readExact(int fd, char* buf, size_t count) {
  size_t pos = 0;
  while (pos < count) {
    pollfd pfd = {fd, POLLIN, 0};
    if (::poll(&pfd, 1, 10000) <= 0) {
      return false;
    }
    ssize_t n = ::read(fd, buf + pos, count - pos);
    if (n <= 0) {
      return false;
    }
    pos += n;
  }
  return true;
}

bool readFrame(int fd, string* body) {
  char length[4];
  if (!readExact(fd, length, 4)) {
    return false;
  }
  uint32_t len = (uint32_t(uint8_t(length[0])) << 24) |
                 (uint32_t(uint8_t(length[1])) << 16) |
                 (uint32_t(uint8_t(length[2])) << 8) | uint8_t(length[3]);
  body->assign(len, '\0');
  return readExact(fd, &(*body)[0], len);
}

int connectUnix(const string& path) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
  REQUIRE(::connect(fd, (sockaddr*)&addr, sizeof(addr)) == 0);
  return fd;
}

// Sends `request` to an agent socket and returns the reply body.
string agentRoundTrip(int fd, const string& request) {
  string reply;
  REQUIRE(writeAll(fd, frame(request)));
  REQUIRE(readFrame(fd, &reply));
  return reply;
}

/**
 * Minimal ssh-agent: serves connections one at a time, recording every
 * request and answering with `reply(request)`; an empty reply closes the
 * connection without answering.
 */
class FakeAgent {
 public:
  explicit FakeAgent(function<string(const string&)> _reply)
      : reply(std::move(_reply)) {
    char dirTemplate[] = "/tmp/et_fake_agent_XXXXXX";
    REQUIRE(mkdtemp(dirTemplate) != nullptr);
    dir = dirTemplate;
    path = dir + "/agent.sock";
    listenFd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    REQUIRE(::bind(listenFd, (sockaddr*)&addr, sizeof(addr)) == 0);
    REQUIRE(::listen(listenFd, 4) == 0);
    worker = std::thread([this]() { serve(); });
  }

  ~FakeAgent() {
    stopping = true;
    worker.join();
    ::close(listenFd);
    ::unlink(path.c_str());
    ::rmdir(dir.c_str());
  }

  vector<string> received() {
    lock_guard<std::mutex> guard(mutex);
    return requests;
  }

  string path;

 private:
  void serve() {
    while (!stopping) {
      pollfd pfd = {listenFd, POLLIN, 0};
      if (::poll(&pfd, 1, 50) <= 0) {
        continue;
      }
      int fd = ::accept(listenFd, nullptr, nullptr);
      string request;
      while (fd >= 0 && waitReadable(fd) && readFrame(fd, &request)) {
        {
          lock_guard<std::mutex> guard(mutex);
          requests.push_back(request);
        }
        string answer = reply(request);
        if (answer.empty() || !writeAll(fd, frame(answer))) {
          break;
        }
      }
      if (fd >= 0) {
        ::close(fd);
      }
    }
  }

  // Waits until fd is readable, giving up promptly once the test is done.
  bool waitReadable(int fd) {
    while (!stopping) {
      pollfd pfd = {fd, POLLIN, 0};
      if (::poll(&pfd, 1, 50) > 0) {
        return true;
      }
    }
    return false;
  }

  function<string(const string&)> reply;
  string dir;
  int listenFd = -1;
  std::atomic<bool> stopping{false};
  std::mutex mutex;
  vector<string> requests;
  std::thread worker;
};

string successReply(const string&) { return string(1, SSH_AGENT_SUCCESS); }

PortForwardDestinationRequest agentDestination(const string& path) {
  PortForwardDestinationRequest request;
  request.mutable_destination()->set_name(path);
  request.set_fd(7);
  return request;
}

void forwardToAgent(PortForwardHandler* handler, int socketId,
                    const string& data) {
  PortForwardData pwd;
  pwd.set_sourcetodestination(true);
  pwd.set_socketid(socketId);
  pwd.set_buffer(data);
  handler->handlePacket(Packet(uint8_t(TerminalPacketType::PORT_FORWARD_DATA),
                               protoToString(pwd)),
                        nullptr);
}

// What the forwarded client receives from the agent, once at least
// `minBytes` arrived (or after about 2 s).
string agentOutput(PortForwardHandler* handler, size_t minBytes) {
  string output;
  for (int i = 0; i < 200 && output.size() < minBytes; i++) {
    vector<PortForwardDestinationRequest> requests;
    vector<PortForwardData> data;
    handler->update(&requests, &data);
    for (const auto& pwd : data) {
      REQUIRE_FALSE(pwd.has_error());
      REQUIRE_FALSE(pwd.has_closed());
      output += pwd.buffer();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return output;
}

/**
 * Plays ssh for SshSetupHandler: `ssh -G` reports no agent, and each real ssh
 * run binds the agent it was handed via -oIdentityAgent to the host keys in
 * `bindsFor(args)`, in order (ProxyJump helpers bind before the final hop).
 */
class BindingSshSubprocess : public SubprocessUtils {
 public:
  explicit BindingSshSubprocess(
      function<vector<string>(const vector<string>&)> _bindsFor)
      : bindsFor(std::move(_bindsFor)) {}

  string SubprocessToStringInteractive(const string& command,
                                       const vector<string>& args) override {
    REQUIRE(command == "ssh");
    if (args[0] == "-G") {
      return "user test\nidentityagent none\n";
    }
    const string prefix = "-oIdentityAgent=";
    string agentPath;
    for (const auto& arg : args) {
      if (arg.compare(0, prefix.size(), prefix) == 0) {
        agentPath = arg.substr(prefix.size());
      }
    }
    REQUIRE_FALSE(agentPath.empty());
    for (const auto& hostKey : bindsFor(args)) {
      int fd = connectUnix(agentPath);
      // No upstream agent: the recorder still answers, with a failure.
      REQUIRE(agentRoundTrip(fd, sessionBind(hostKey, false)) ==
              string(1, SSH_AGENT_FAILURE));
      ::close(fd);
    }
    return "IDPASSKEY:" + genRandomAlphaNum(16) + "/" + genRandomAlphaNum(32);
  }

  function<vector<string>(const vector<string>&)> bindsFor;
};
#endif
}  // namespace

TEST_CASE("forwardedSessionBind marks ssh's own binding as forwarded",
          "[SshAgentSessionBind]") {
  auto forwarded = forwardedSessionBind(sessionBind("host-key", false));
  REQUIRE(forwarded);
  REQUIRE(*forwarded == sessionBind("host-key", true));
}

TEST_CASE("forwardedSessionBind rejects other agent messages",
          "[SshAgentSessionBind]") {
  string bind = sessionBind("host-key", false);
  CHECK_FALSE(forwardedSessionBind(sessionBind("host-key", true)));
  CHECK_FALSE(forwardedSessionBind(string(1, SSH_AGENTC_REQUEST_IDENTITIES)));
  CHECK_FALSE(forwardedSessionBind(""));
  CHECK_FALSE(forwardedSessionBind(bind.substr(0, bind.size() - 1)));
  CHECK_FALSE(forwardedSessionBind(bind + "x"));
  CHECK_FALSE(forwardedSessionBind(string(1, char(27)) + sshString("query") +
                                   sshString("x")));
  CHECK_FALSE(forwardedSessionBind(sessionBind("", false)));
}

TEST_CASE("sessionBindHostKeyFingerprint matches ssh-keygen",
          "[SshAgentSessionBind]") {
  string hostKey;
  REQUIRE(Base64::Decode(
      "AAAAC3NzaC1lZDI1NTE5AAAAID4NdJ9B1LOS7+li7shEB10b9lQEjdsbe2oNQEW8fZP7",
      &hostKey));
  CHECK(sessionBindHostKeyFingerprint(sessionBind(hostKey, true)) ==
        "SHA256:1Z8TElQaniPWrBI8ZeIOaUH5BDBpeoK85Bt65Kr7ppY");
  CHECK_FALSE(
      sessionBindHostKeyFingerprint(string(1, SSH_AGENTC_REQUEST_IDENTITIES)));
}

TEST_CASE("AgentSessionBindReplies drops only the bind replies",
          "[SshAgentSessionBind]") {
  string bindReplies =
      frame(string(1, SSH_AGENT_SUCCESS)) + frame(string(1, SSH_AGENT_FAILURE));
  string clientReply = frame(string(1, SSH_AGENT_IDENTITIES_ANSWER) + u32(0));

  SECTION("Replies split across reads") {
    AgentSessionBindReplies replies(2, "/tmp/agent.sock");
    string stream = bindReplies + clientReply;
    string forwarded;
    for (char byte : stream) {
      string out;
      REQUIRE(replies.consume(string(1, byte), &out));
      forwarded += out;
    }
    CHECK(forwarded == clientReply);
  }

  SECTION("Client data in the same read as the last bind reply") {
    AgentSessionBindReplies replies(2, "/tmp/agent.sock");
    string out;
    REQUIRE(replies.consume(bindReplies.substr(0, 3), &out));
    CHECK(out.empty());
    REQUIRE(replies.consume(bindReplies.substr(3) + clientReply, &out));
    CHECK(out == clientReply);
    REQUIRE(replies.consume("more", &out));
    CHECK(out == "more");
  }

  SECTION("Malformed reply length") {
    AgentSessionBindReplies replies(1, "/tmp/agent.sock");
    string out;
    CHECK_FALSE(replies.consume(u32(0) + "x", &out));
  }
}

TEST_CASE("sshIdentityAgentFromConfigDump follows ssh IdentityAgent rules",
          "[SshAgentSessionBind]") {
#ifdef WIN32
  SKIP("setenv/unsetenv");
#else
  const char* originalAuthSock = getenv("SSH_AUTH_SOCK");
  optional<string> savedAuthSock =
      originalAuthSock ? optional<string>(originalAuthSock) : nullopt;
  setenv("SSH_AUTH_SOCK", "/tmp/env-agent.sock", 1);
  setenv("ET_TEST_AGENT", "/tmp/var-agent.sock", 1);
  unsetenv("ET_TEST_UNSET_AGENT");

  CHECK(sshIdentityAgentFromConfigDump("user me\nport 22\n") ==
        "/tmp/env-agent.sock");
  CHECK(sshIdentityAgentFromConfigDump("identityagent SSH_AUTH_SOCK\n") ==
        "/tmp/env-agent.sock");
  CHECK(sshIdentityAgentFromConfigDump("identityagent none\n") == "");
  CHECK(sshIdentityAgentFromConfigDump("identityagent $ET_TEST_AGENT\n") ==
        "/tmp/var-agent.sock");
  CHECK(sshIdentityAgentFromConfigDump(
            "identityagent $ET_TEST_UNSET_AGENT\n") == "");
  CHECK(sshIdentityAgentFromConfigDump(
            "port 22\nidentityagent /home/me/.1password/agent.sock\n") ==
        "/home/me/.1password/agent.sock");

  unsetenv("SSH_AUTH_SOCK");
  CHECK(sshIdentityAgentFromConfigDump("user me\n") == "");

  unsetenv("ET_TEST_AGENT");
  if (savedAuthSock) {
    setenv("SSH_AUTH_SOCK", savedAuthSock->c_str(), 1);
  }
#endif
}

TEST_CASE("SshAgentSessionBindRecorder relays to the agent and records binds",
          "[SshAgentSessionBind]") {
#ifdef WIN32
  SKIP("Unix-domain ssh-agent sockets");
#else
  FakeAgent agent([](const string& request) {
    if (request[0] == SSH_AGENTC_REQUEST_IDENTITIES) {
      return string(1, SSH_AGENT_IDENTITIES_ANSWER) + u32(0);
    }
    return string(1, SSH_AGENT_SUCCESS);
  });
  SshAgentSessionBindRecorder recorder(agent.path);
  CHECK_FALSE(recorder.lastForwardedBind());

  // A ProxyJump helper binds first; ssh binds the destination last.
  int jumpFd = connectUnix(recorder.socketPath());
  CHECK(agentRoundTrip(jumpFd, sessionBind("jump-key", false)) ==
        string(1, SSH_AGENT_SUCCESS));
  // The fake agent serves one connection at a time.
  ::close(jumpFd);
  int fd = connectUnix(recorder.socketPath());
  CHECK(agentRoundTrip(fd, sessionBind("dest-key", false)) ==
        string(1, SSH_AGENT_SUCCESS));
  CHECK(agentRoundTrip(fd, string(1, SSH_AGENTC_REQUEST_IDENTITIES)) ==
        string(1, SSH_AGENT_IDENTITIES_ANSWER) + u32(0));

  ::close(fd);

  REQUIRE(recorder.lastForwardedBind() == sessionBind("dest-key", true));
  // ssh's own binding reaches the real agent unchanged.
  auto received = agent.received();
  REQUIRE(received.size() == 3);
  CHECK(received[0] == sessionBind("jump-key", false));
  CHECK(received[1] == sessionBind("dest-key", false));
#endif
}

TEST_CASE("SshAgentSessionBindRecorder without an agent fails requests",
          "[SshAgentSessionBind]") {
#ifdef WIN32
  SKIP("Unix-domain ssh-agent sockets");
#else
  string socketPath;
  {
    SshAgentSessionBindRecorder recorder("");
    socketPath = recorder.socketPath();
    int fd = connectUnix(socketPath);
    CHECK(agentRoundTrip(fd, string(1, SSH_AGENTC_REQUEST_IDENTITIES)) ==
          string(1, SSH_AGENT_FAILURE));
    CHECK(agentRoundTrip(fd, sessionBind("dest-key", false)) ==
          string(1, SSH_AGENT_FAILURE));
    ::close(fd);
    CHECK(recorder.lastForwardedBind() == sessionBind("dest-key", true));
  }
  CHECK_FALSE(fs::exists(fs::path(socketPath).parent_path()));
#endif
}

TEST_CASE("Forwarded agent connections are bound before data flows",
          "[SshAgentSessionBind]") {
#ifdef WIN32
  SKIP("Unix-domain ssh-agent sockets");
#else
  vector<string> binds = {sessionBind("jump-key", true),
                          sessionBind("dest-key", true)};
  auto pipeHandler = make_shared<PipeSocketHandler>();
  PortForwardHandler handler(make_shared<TcpSocketHandler>(), pipeHandler);

  SECTION("Bindings precede forwarded requests and their replies are hidden") {
    FakeAgent agent(successReply);
    handler.setSshAgentSessionBinds(agent.path, binds);
    auto response = handler.createDestination(agentDestination(agent.path));
    REQUIRE_FALSE(response.has_error());

    forwardToAgent(&handler, response.socketid(),
                   frame(string(1, SSH_AGENTC_REQUEST_IDENTITIES)));
    string expected = frame(string(1, SSH_AGENT_SUCCESS));
    CHECK(agentOutput(&handler, expected.size()) == expected);

    auto received = agent.received();
    REQUIRE(received.size() == 3);
    CHECK(received[0] == binds[0]);
    CHECK(received[1] == binds[1]);
    CHECK(received[2] == string(1, SSH_AGENTC_REQUEST_IDENTITIES));
  }

  SECTION("Agents without the extension are still forwarded") {
    FakeAgent agent([](const string&) { return string(1, SSH_AGENT_FAILURE); });
    handler.setSshAgentSessionBinds(agent.path, binds);
    auto response = handler.createDestination(agentDestination(agent.path));
    REQUIRE_FALSE(response.has_error());

    forwardToAgent(&handler, response.socketid(),
                   frame(string(1, SSH_AGENTC_REQUEST_IDENTITIES)));
    string expected = frame(string(1, SSH_AGENT_FAILURE));
    CHECK(agentOutput(&handler, expected.size()) == expected);
  }

  SECTION("A slow agent does not block the client") {
    std::promise<void> release;
    auto released = release.get_future().share();
    FakeAgent agent([released](const string&) {
      released.wait_for(std::chrono::seconds(5));
      return string(1, SSH_AGENT_SUCCESS);
    });
    handler.setSshAgentSessionBinds(agent.path, binds);

    auto start = std::chrono::steady_clock::now();
    auto response = handler.createDestination(agentDestination(agent.path));
    CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(2));
    REQUIRE_FALSE(response.has_error());

    forwardToAgent(&handler, response.socketid(),
                   frame(string(1, SSH_AGENTC_REQUEST_IDENTITIES)));
    CHECK(agentOutput(&handler, 1).empty());
    release.set_value();
    string expected = frame(string(1, SSH_AGENT_SUCCESS));
    CHECK(agentOutput(&handler, expected.size()) == expected);
  }

  SECTION("Other unix sockets are not bound") {
    FakeAgent agent(successReply);
    FakeAgent otherSocket(successReply);
    handler.setSshAgentSessionBinds(agent.path, binds);
    auto response =
        handler.createDestination(agentDestination(otherSocket.path));
    REQUIRE_FALSE(response.has_error());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    CHECK(otherSocket.received().empty());
  }
#endif
}

TEST_CASE("SshSetupHandler records agent bindings in hop order",
          "[SshAgentSessionBind]") {
#ifdef WIN32
  SKIP("The agent proxy is not built on Windows");
#else
  auto ssh = make_shared<BindingSshSubprocess>([](const vector<string>& args) {
    bool viaJumphost = std::find(args.begin(), args.end(), "-J") != args.end();
    // ssh -J runs a ProxyJump helper that binds the jumphost before the
    // destination; the direct jumphost ssh binds only the jumphost.
    return viaJumphost ? vector<string>{"jump-key", "dest-key"}
                       : vector<string>{"jump-key"};
  });
  SshSetupHandler handler(ssh);
  handler.setCaptureAgentSessionBinds(true);

  handler.SetupSsh("user", "dest", "dest", 2022, "jumphost", "", false, 0, "",
                   "", {});

  CHECK(handler.agentSessionBinds() ==
        vector<string>{sessionBind("jump-key", true),
                       sessionBind("dest-key", true)});
#endif
}
