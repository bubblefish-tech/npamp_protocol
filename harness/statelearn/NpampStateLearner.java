// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// NpampStateLearner is the T18.2 LearnLib driver (R18.2): it actively learns the N-PAMP Go
// SDK's REAL Mealy state machine — via the statelearn-sul binary (sul/), which drives the
// real sdk.DialRaw/sdk.AcceptRaw/Conn.Recv/Conn.CloseGraceful over an in-process net.Pipe
// — for BOTH the initiator and responder roles, using LearnLib 0.18.0's TTT
// algorithm with a Wp-method equivalence oracle. It exports each learned model as DOT
// (learned-<role>.dot) and a plain JSON transition table (learned-<role>.json) for
// diff_model.py (the F3-independent comparison against harness/statemodel's draft-derived
// reference table), and records the run's parameters/statistics to learn-config.json.
//
// Build/run (no Maven; the ONE verified uber-jar carries LearnLib 0.18.0 + AutomataLib 0.12.0
// + Guava + SLF4J-NOP on the classpath):
//   javac -cp lib/learnlib-distribution-0.18.0-dependencies-bundle.jar -d classes *.java
//   java  -cp "lib/learnlib-distribution-0.18.0-dependencies-bundle.jar;classes" \
//         NpampStateLearner sul/statelearn-sul.exe .

import de.learnlib.algorithm.ttt.mealy.TTTLearnerMealy;
import de.learnlib.algorithm.ttt.mealy.TTTLearnerMealyBuilder;
import de.learnlib.oracle.equivalence.MealyRandomWpMethodEQOracle;
import de.learnlib.oracle.membership.SULOracle;
import de.learnlib.util.Experiment;
import net.automatalib.alphabet.Alphabet;
import net.automatalib.alphabet.impl.GrowingMapAlphabet;
import net.automatalib.automaton.transducer.MealyMachine;
import net.automatalib.serialization.dot.GraphDOT;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public final class NpampStateLearner {

    /** The learnable input alphabet: input_alphabet minus modeled_exclusions, plus the
     * ACTION symbol INIT_CLOSE (see harness/statemodel/npamp-state-table.json and
     * harness/statelearn/README.md). */
    static final String[] ALPHABET = {
            "CLIENT_HELLO", "SERVER_HELLO", "SERVER_HELLO_BADSEL", "SERVER_AUTH",
            "SERVER_AUTH_BADAUTH", "CLIENT_AUTH", "CLIENT_AUTH_BADAUTH", "KEY_UPDATE",
            "KEY_UPDATE_ACK", "CLOSE", "CLOSE_ACK", "APP", "UNKNOWN", "INIT_CLOSE"
    };
    // Equivalence-oracle configuration — RANDOMIZED Wp-method (MealyRandomWpMethodEQOracle).
    //
    // TTT membership-learning discovers the state machine cheaply; the equivalence oracle then
    // searches for a state the hypothesis missed. The EXHAUSTIVE Wp-method enumerates every
    // distinguishing test word up to a fixed middle-length depth d, a set that grows as
    // |transitionCover| · Σ_{i=0..d}|alphabet|^i · |charSet| — for this 14-symbol alphabet that
    // is ~145k full protocol episodes at d=2 and ~2M at d=3, neither of which finishes in a
    // practical wall-clock over the (necessarily timeout-probed) net.Pipe transport. This is
    // intrinsic to the m-complete guarantee, not a property of the transport: an m-complete
    // suite is exponential in the extra-state bound (Chow 1978; Fujiwara et al. 1991).
    //
    // The standard, literature-grounded way to make active learning of a real protocol scale
    // (de Ruiter & Poll, USENIX Security 2015, TLS state fuzzing; Fiterău-Broștean et al.,
    // TCP/SSH/QUIC) is to RANDOMIZE the Wp-method: sample the same test-word space (a prefix
    // from the state/transition cover, a geometric-length random middle, a suffix from the
    // characterization set) to a fixed test BUDGET rather than enumerate it. This trades the
    // exhaustive certainty for a strong probabilistic guarantee, at a controllable cost, and —
    // because the middle length is geometric — it can reach LONGER distinguishing sequences than
    // any fixed-depth exhaustive run, so it does not shrink the reachable fault space the way a
    // smaller depth would. F3 is preserved: the oracle still learns the REAL SDK and the diff
    // still compares against the draft-derived table.
    //
    // EQ_MINIMAL_SIZE / EQ_RND_LENGTH: the random middle word has minimal length EQ_MINIMAL_SIZE
    // plus a geometrically-distributed extra length with expectation EQ_RND_LENGTH (expected
    // middle length = EQ_MINIMAL_SIZE + EQ_RND_LENGTH). EQ_BOUND: the number of random test
    // words per equivalence-query invocation (MUST be > 0 — an unbounded RandomWp never
    // terminates on a correct hypothesis). EQ_SEED: fixed so a clean/again run is reproducible.
    // The single-step divergences this harness targets (unsolicited-ack rejection, drop-and-
    // survive) are caught DETERMINISTICALLY by TTT's membership queries (which probe every
    // symbol from every discovered state), not by this sampled oracle — so the recorded mutation
    // (M1) flips the diff RED regardless of the random seed; the oracle's job is only to hunt
    // for a MISSED state, and the bound is sized (see learn-config.json) from a measured
    // seconds-per-test so a full learn of both roles fits a practical wall-clock.
    static final int EQ_MINIMAL_SIZE = 1;
    static final int EQ_RND_LENGTH = 4;
    static final int EQ_BOUND = 2000;
    static final long EQ_SEED = 0x6E70616D70L; // "npamp" — fixed for reproducibility
    static final String[] ROLES = {"initiator", "responder"};

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: NpampStateLearner <sul-binary-path> <output-dir>");
            System.exit(2);
        }
        String sulBinary = args[0];
        String outDir = args[1];
        Files.createDirectories(Paths.get(outDir));

        Map<String, RoleResult> results = new LinkedHashMap<>();
        for (String role : ROLES) {
            System.out.println("=== learning role=" + role + " ===");
            results.put(role, learnRole(sulBinary, outDir, role));
        }
        writeConfig(outDir, results);

        System.out.println("=== summary ===");
        for (Map.Entry<String, RoleResult> e : results.entrySet()) {
            RoleResult r = e.getValue();
            System.out.println(e.getKey() + ": states=" + r.states + " transitions=" + r.transitions
                    + " resets=" + r.resetCount + " queries=" + r.queryCount + " wallclock_ms=" + r.wallclockMs);
        }
    }

    static final class RoleResult {
        int states;
        int transitions;
        long resetCount;
        long queryCount;
        long wallclockMs;
    }

    static RoleResult learnRole(String sulBinary, String outDir, String role) throws IOException {
        GoProcessSUL sul = new GoProcessSUL(sulBinary, role);
        try {
            Alphabet<String> alphabet = new GrowingMapAlphabet<>(Arrays.asList(ALPHABET));

            SULOracle<String, String> mq = new SULOracle<>(sul);
            TTTLearnerMealy<String, String> learner = new TTTLearnerMealyBuilder<String, String>()
                    .withAlphabet(alphabet)
                    .withOracle(mq)
                    .create();
            MealyRandomWpMethodEQOracle<String, String> eq = new MealyRandomWpMethodEQOracle<>(
                    mq, EQ_MINIMAL_SIZE, EQ_RND_LENGTH, EQ_BOUND, new Random(EQ_SEED), 1);

            Experiment.MealyExperiment<String, String> experiment =
                    new Experiment.MealyExperiment<>(learner, eq, alphabet);
            experiment.setLogModels(false);
            experiment.setProfile(false);

            long t0 = System.currentTimeMillis();
            experiment.run();
            long wallclockMs = System.currentTimeMillis() - t0;

            MealyMachine<?, String, ?, String> model = experiment.getFinalHypothesis();

            try (Writer w = new FileWriter(outDir + "/learned-" + role + ".dot", StandardCharsets.US_ASCII)) {
                GraphDOT.write(model, alphabet, w);
            }

            LearnedModel lm = LearnedModel.extract(model, alphabet);
            lm.writeJSON(outDir + "/learned-" + role + ".json");

            RoleResult r = new RoleResult();
            r.states = lm.states.size();
            r.transitions = lm.transitions.size();
            r.resetCount = sul.getResetCount();
            r.queryCount = sul.getQueryCount();
            r.wallclockMs = wallclockMs;
            return r;
        } finally {
            sul.shutdown();
        }
    }

    static void writeConfig(String outDir, Map<String, RoleResult> results) throws IOException {
        try (Writer w = new FileWriter(outDir + "/learn-config.json", StandardCharsets.UTF_8)) {
            w.write("{\n");
            w.write("  \"tool\": \"LearnLib\",\n");
            w.write("  \"version\": \"0.18.0\",\n");
            w.write("  \"automatalib_version\": \"0.12.0\",\n");
            w.write("  \"algorithm\": \"TTT\",\n");
            w.write("  \"eq_oracle\": \"randomized-Wp-method\",\n");
            w.write("  \"eq_oracle_class\": \"de.learnlib.oracle.equivalence.MealyRandomWpMethodEQOracle\",\n");
            w.write("  \"eq_minimal_size\": " + EQ_MINIMAL_SIZE + ",\n");
            w.write("  \"eq_rnd_length\": " + EQ_RND_LENGTH + ",\n");
            w.write("  \"eq_bound_tests_per_query\": " + EQ_BOUND + ",\n");
            w.write("  \"eq_seed\": " + EQ_SEED + ",\n");
            w.write("  \"eq_note\": \"exhaustive Wp is exponential in the extra-state bound (Chow 1978; Fujiwara"
                    + " et al. 1991) -> ~145k episodes at depth 2, infeasible over the timeout-probed net.Pipe;"
                    + " randomized Wp samples the same test-word space to a fixed budget, the standard practice"
                    + " for real protocol SULs (de Ruiter & Poll USENIX'15; Fiterau-Brostean et al). Single-step"
                    + " divergences are caught deterministically by TTT membership queries, not this oracle.\",\n");
            w.write("  \"alphabet\": [");
            List<String> quoted = new ArrayList<>();
            for (String s : ALPHABET) {
                quoted.add(LearnedModel.jsonStr(s));
            }
            w.write(String.join(", ", quoted));
            w.write("],\n");
            w.write("  \"seed\": \"identities fixed (sul/identity.go: driver 0x11, SUT 0x22 byte-repeated"
                    + " Ed25519 seeds); ML-KEM-768/X25519 ephemeral material is UNSEEDED real"
                    + " crypto/mlkem/crypto/ecdh randomness -- see identity_determinism\",\n");
            w.write("  \"identity_determinism\": \"fixed Ed25519 seeds for both the driver and the SUT identity"
                    + " (sul/identity.go); ML-KEM/X25519 ephemeral material is real crypto/mlkem and"
                    + " crypto/ecdh randomness (never overridden), which is safe because every SUL output is"
                    + " abstracted to a frame-type/error-code symbol, not raw bytes\",\n");
            w.write("  \"roles\": {\n");
            int i = 0;
            for (Map.Entry<String, RoleResult> e : results.entrySet()) {
                RoleResult r = e.getValue();
                w.write("    " + LearnedModel.jsonStr(e.getKey()) + ": {\n");
                w.write("      \"states\": " + r.states + ",\n");
                w.write("      \"transitions\": " + r.transitions + ",\n");
                w.write("      \"reset_count\": " + r.resetCount + ",\n");
                w.write("      \"membership_query_count\": " + r.queryCount + ",\n");
                w.write("      \"wallclock_ms\": " + r.wallclockMs + "\n");
                w.write("    }");
                w.write(++i < results.size() ? ",\n" : "\n");
            }
            w.write("  }\n");
            w.write("}\n");
        }
    }
}
