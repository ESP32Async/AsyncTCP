// Shared test fixtures: the addresses the tests dial and listen on, and the steps most
// tests start with.
#ifndef ASYNCTCP_TEST_FIXTURES_H
#define ASYNCTCP_TEST_FIXTURES_H

#include "runner.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "AsyncTCP.h"
#include "mocks/mock_alloc.h"
#include "mocks/mock_lwip.h"
#include "mocks/mock_rtos.h"

extern "C" {
#include "lwip/tcp.h"
}

const IPAddress kPeer(10, 0, 0, 1);     // where clients dial
const uint16_t kPort = 8080;            // ... and on what port
const uint16_t kServerPort = 8081;      // where servers listen
const uint32_t kResolved = 0x0A000005;  // what a name lookup answers: 10.0.0.5
const long kExpectedBacklog = 5;        // what a server asks lwIP for; there is no public setting

// Connects to kPeer and completes the handshake.  Returns the client's pcb.
inline tcp_pcb *establish(AsyncClient &c) {
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  tcp_pcb *pcb = mocklwip::dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_INT((int)ERR_OK, (int)mocklwip::fire_connected(pcb));
  asynctcp_test_pump();
  TEST_ASSERT_TRUE(c.connected());
  return pcb;
}

// The listening pcb on <port>, or on any port when it is 0.  nullptr if there is none.
inline tcp_pcb *listen_pcb(uint16_t port = 0) {
  for (tcp_pcb *p : mocklwip::pcbs()) {
    if (p->state == LISTEN && (port == 0 || p->local_port == port)) {
      return p;
    }
  }
  return nullptr;
}

// The application calling into the library, from a test body or from inside a callback.
// Open one around each call.  Callbacks run on the async task, never inside a call, except
// that close() and ~AsyncClient() may run the client's own onDisconnect, and abort() its
// own onError(ERR_ABRT) then onDisconnect.
class AppCall {
public:
  // <name> is what is called, on <client> if anything; <may_run> is the letters it may run
  // for that client (see Recorder).
  explicit AppCall(const char *name, const AsyncClient *client = nullptr, const char *may_run = "")
    : _name(name), _client(client), _may_run(may_run), _outer(_current) {
    _current = this;
  }
  ~AppCall() {
    _current = _outer;
  }
  AppCall(const AppCall &) = delete;
  AppCall &operator=(const AppCall &) = delete;

  // The innermost call open, or nullptr while the library runs on its own.
  static const AppCall *current() {
    return _current;
  }
  const char *name() const {
    return _name;
  }
  bool allows(char event, const AsyncClient *c, int8_t err) const {
    if (c != _client || !strchr(_may_run, event)) {
      return false;
    }
    return event != 'E' || err == ERR_ABRT;
  }

private:
  const char *_name;
  const AsyncClient *_client;
  const char *_may_run;
  const AppCall *_outer;
  static inline const AppCall *_current = nullptr;
};

// Runs <f> as the application call <name>, which may run no callbacks.
template<class F> auto app(const char *name, F &&f) {
  AppCall call(name);
  return f();
}
inline void app_close(AsyncClient &c) {
  AppCall call("close", &c, "D");
  c.close();
}
inline int8_t app_abort(AsyncClient &c) {
  AppCall call("abort", &c, "ED");
  return c.abort();
}
inline void app_delete(AsyncClient *c) {
  AppCall call("~AsyncClient", c, "D");
  delete c;
}

// Records a client's callbacks as one letter each, in the order they run, so that order,
// count and exactly-once are one assertion: "ED" is onError then onDisconnect, "" is
// silence.
//
//   C onConnect   E onError   D onDisconnect   R onData
//   A onAck       P onPoll    T onTimeout      K onPacket, which acks the pbuf
//
// attach() registers only the callbacks it is given -- by default the three that open and
// end a connection -- because registering a handler can change what the library does.
//
// A callback run inside an AppCall that does not allow it is added to <violations>.
class Recorder {
public:
  std::string seq;
  int8_t err = 0;          // what the last onError was given
  std::string data;        // everything onData or onPacket was given, concatenated
  size_t acked = 0;        // what the last onAck was given
  uint32_t timed_out = 0;  // what the last onTimeout was given
  std::string violations;  // "R in write(); ..."

  Recorder() = default;
  Recorder(const Recorder &) = delete;
  Recorder &operator=(const Recorder &) = delete;

  void attach(AsyncClient &c, const char *events = "CED") {
    if (strchr(events, 'C')) {
      c.onConnect([this](void *, AsyncClient *cl) {
        note('C', cl);
      });
    }
    if (strchr(events, 'E')) {
      c.onError([this](void *, AsyncClient *cl, int8_t e) {
        note('E', cl, e);
        err = e;
      });
    }
    if (strchr(events, 'D')) {
      c.onDisconnect([this](void *, AsyncClient *cl) {
        note('D', cl);
      });
    }
    if (strchr(events, 'R')) {
      c.onData([this](void *, AsyncClient *cl, void *d, size_t n) {
        note('R', cl);
        data.append((const char *)d, n);
      });
    }
    if (strchr(events, 'A')) {
      c.onAck([this](void *, AsyncClient *cl, size_t n, uint32_t t) {
        note('A', cl);
        acked = n;
      });
    }
    if (strchr(events, 'P')) {
      c.onPoll([this](void *, AsyncClient *cl) {
        note('P', cl);
      });
    }
    if (strchr(events, 'T')) {
      c.onTimeout([this](void *, AsyncClient *cl, uint32_t t) {
        note('T', cl);
        timed_out = t;
      });
    }
    if (strchr(events, 'K')) {
      c.onPacket([this](void *, AsyncClient *cl, pbuf *pb) {
        note('K', cl);
        data.append((const char *)pb->payload, pb->len);
        AppCall call("ackPacket");
        cl->ackPacket(pb);
      });
    }
  }

  // Records <event> for client <c>, as the handlers attach() registers do.
  void note(char event, const AsyncClient *c, int8_t e = 0) {
    seq += event;
    const AppCall *call = AppCall::current();
    if (call && !call->allows(event, c, e)) {
      violations += event;
      violations += std::string(" in ") + call->name() + "(); ";
    }
  }

  int count(char event) const {
    return (int)std::count(seq.begin(), seq.end(), event);
  }
};

// Takes delivery of a server's clients, in order, and deletes whatever is left of them when
// it goes out of scope.  <setup> runs on each client as it is delivered.
class Accepted {
public:
  explicit Accepted(AsyncServer &s, std::function<void(AsyncClient *)> setup = nullptr) {
    s.onClient(
      [this, setup](void *, AsyncClient *c) {
        _clients.push_back(c);
        if (setup) {
          setup(c);
        }
      },
      nullptr
    );
  }
  ~Accepted() {
    clear();
  }
  Accepted(const Accepted &) = delete;
  Accepted &operator=(const Accepted &) = delete;

  size_t size() const {
    return _clients.size();
  }
  AsyncClient *operator[](size_t i) const {
    return _clients.at(i);
  }
  // The client holding <pcb>, or nullptr.
  AsyncClient *holding(const tcp_pcb *pcb) const {
    for (AsyncClient *c : _clients) {
      if (c->pcb() == pcb) {
        return c;
      }
    }
    return nullptr;
  }
  // Deletes the i-th client now.
  void drop(size_t i) {
    AsyncClient *c = _clients.at(i);
    _clients.erase(_clients.begin() + i);
    delete c;
  }
  void clear() {
    std::vector<AsyncClient *> doomed;
    doomed.swap(_clients);
    for (AsyncClient *c : doomed) {
      delete c;
    }
  }

private:
  std::vector<AsyncClient *> _clients;
};

#endif
