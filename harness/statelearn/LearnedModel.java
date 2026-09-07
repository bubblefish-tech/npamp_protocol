// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// LearnedModel walks a LearnLib-produced net.automatalib MealyMachine (over the fixed
// String,String alphabet this harness learns) into a plain, JSON-serializable form the
// Python diff tool (diff_model.py) consumes. GraphDOT.write covers the human-readable export
// (learned-<role>.dot); this is the machine-readable one (no JSON library ships in the
// LearnLib uber-jar, so the writer is hand-rolled for this small, fully-controlled shape).

import net.automatalib.alphabet.Alphabet;
import net.automatalib.automaton.transducer.MealyMachine;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class LearnedModel {
    static final class Transition {
        final String from;
        final String input;
        final String to;
        final String output;

        Transition(String from, String input, String to, String output) {
            this.from = from;
            this.input = input;
            this.to = to;
            this.output = output;
        }
    }

    final List<String> states = new ArrayList<>();
    String initialState;
    final List<Transition> transitions = new ArrayList<>();

    static <S> LearnedModel extract(MealyMachine<S, String, ?, String> model, Alphabet<String> alphabet) {
        LearnedModel lm = new LearnedModel();
        Map<S, String> ids = new LinkedHashMap<>();
        int n = 0;
        for (S s : model.getStates()) {
            ids.put(s, "q" + n);
            n++;
        }
        for (S s : model.getStates()) {
            lm.states.add(ids.get(s));
        }
        lm.initialState = ids.get(model.getInitialState());
        for (S s : model.getStates()) {
            for (String in : alphabet) {
                S succ = model.getSuccessor(s, in);
                if (succ == null) {
                    // A complete SUL (this one always returns SOME output symbol) should
                    // never leave a cell unreachable; record nothing rather than fabricate a
                    // transition if it ever does.
                    continue;
                }
                String out = model.getOutput(s, in);
                lm.transitions.add(new Transition(ids.get(s), in, ids.get(succ), out));
            }
        }
        return lm;
    }

    void writeJSON(String path) throws IOException {
        try (Writer w = new OutputStreamWriter(new FileOutputStream(path), StandardCharsets.UTF_8)) {
            w.write("{\n");
            w.write("  \"initial_state\": " + jsonStr(initialState) + ",\n");
            w.write("  \"states\": [");
            for (int i = 0; i < states.size(); i++) {
                if (i > 0) {
                    w.write(", ");
                }
                w.write(jsonStr(states.get(i)));
            }
            w.write("],\n");
            w.write("  \"transitions\": [\n");
            for (int i = 0; i < transitions.size(); i++) {
                Transition t = transitions.get(i);
                w.write("    {\"from\": " + jsonStr(t.from) + ", \"input\": " + jsonStr(t.input)
                        + ", \"to\": " + jsonStr(t.to) + ", \"output\": " + jsonStr(t.output) + "}");
                w.write(i + 1 < transitions.size() ? ",\n" : "\n");
            }
            w.write("  ]\n");
            w.write("}\n");
        }
    }

    static String jsonStr(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    b.append("\\\"");
                    break;
                case '\\':
                    b.append("\\\\");
                    break;
                case '\n':
                    b.append("\\n");
                    break;
                default:
                    b.append(c);
            }
        }
        return b.append('"').toString();
    }
}
