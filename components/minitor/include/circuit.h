typedef struct Relay Relay;
typedef struct Circuit Circuit;
typedef struct LinkedCircuit LinkedCircuit;

typedef struct HiddenService {
  int hidden_service_id;
  Circuit* intro_one;
  Circuit* intro_two;
  Circuit* ready_circuit;
  LinkedCircuit* first_circuit;
} HiddenService;

struct LinkedCircuit {
  Circuit* circuit;
  Circuit* next_circuit;
};

struct Circuit {
  int circ_id;
  Relay* first_hop;
  Relay* last_hop;
};

struct Relay {
  Relay* next;
  Relay* previous;
};
