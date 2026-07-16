<?php

/**
 * Corpus conformance test for the eight N-PAMP native-channel body decoders.
 *
 * Grades the PHP decoders (src/NpampBodies.php) against the SHARED, independent
 * conformance corpus (test-vectors/v1/conformance-corpus.json) — the same corpus
 * the Go/Python oracles grade against. The corpus is the grader: for every vector
 * whose result is "valid" or "acceptable" the body MUST decode without error and
 * (where the corpus declares them) the decoded frame_kind and corr MUST match; for
 * every "invalid" vector the body MUST produce a decode error (BodyException or
 * CborException). Any OTHER thrown type on an invalid vector is itself a failure —
 * a decoder that reject-by-crash is not honestly rejecting.
 *
 * Prints one line per op-group and a final tally; exits 0 only if every vector in
 * every one of the eight op-groups graded as the corpus demands.
 *
 * Run from impl/php:  php test/BodyCorpusTest.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/NpampBodies.php';

use Sh\Bubblefish\Npamp\Bodies;
use Sh\Bubblefish\Npamp\BodyException;
use Sh\Bubblefish\Npamp\CborException;
use Sh\Bubblefish\Npamp\CBytes;
use Sh\Bubblefish\Npamp\CUint;

// Repo-relative: impl/php/test -> ../../../test-vectors/v1/conformance-corpus.json
$corpusPath = __DIR__ . '/../../../test-vectors/v1/conformance-corpus.json';
if (!is_file($corpusPath)) {
    fwrite(STDERR, "corpus not found at {$corpusPath}\n");
    exit(2);
}
$corpus = json_decode((string) file_get_contents($corpusPath), true, 512, JSON_THROW_ON_ERROR);

$ops = [
    'capability.body.decode',
    'immune.body.decode',
    'settlement.body.decode',
    'telemetry.body.decode',
    'commerce.body.decode',
    'interaction.body.decode',
    'workflow.body.decode',
    'knowledge.body.decode',
];

/** Index the corpus test groups by op string. */
$groups = [];
foreach ($corpus['testGroups'] as $g) {
    $groups[$g['op']] = $g;
}

$totalPass = 0;
$totalFail = 0;
$failedOps = [];

foreach ($ops as $op) {
    if (!isset($groups[$op])) {
        echo "FAIL - {$op}: op-group absent from corpus\n";
        $failedOps[] = $op;
        $totalFail++;
        continue;
    }
    $tests = $groups[$op]['tests'];
    $pass = 0;
    $fail = 0;
    foreach ($tests as $t) {
        $tcId = $t['tcId'] ?? '?';
        $ft = (int) $t['in']['frameType'];
        $bodyHex = (string) $t['in']['body'];
        $body = $bodyHex === '' ? '' : (string) hex2bin($bodyHex);
        $result = (string) $t['result'];

        if ($result === 'valid' || $result === 'acceptable') {
            try {
                $m = Bodies::decode($op, $ft, $body);
            } catch (\Throwable $e) {
                echo "  FAIL {$op} tc{$tcId}: expected decode OK, got " . $e::class . ": {$e->getMessage()}\n";
                $fail++;
                continue;
            }
            $exp = $t['expected'] ?? [];
            $ok = true;
            if (isset($exp['frame_kind'])) {
                [$fk, $has] = $m->get(0);
                if (!$has || !($fk instanceof CUint) || $fk->v !== (int) $exp['frame_kind']) {
                    $got = ($fk instanceof CUint) ? $fk->v : 'absent';
                    echo "  FAIL {$op} tc{$tcId}: frame_kind mismatch (got {$got}, want {$exp['frame_kind']})\n";
                    $ok = false;
                }
            }
            if (isset($exp['corr'])) {
                [$corr, $has] = $m->get(1);
                $gotCorr = ($corr instanceof CBytes) ? bin2hex($corr->v) : 'absent';
                if (!$has || !($corr instanceof CBytes) || $gotCorr !== (string) $exp['corr']) {
                    echo "  FAIL {$op} tc{$tcId}: corr mismatch (got {$gotCorr}, want {$exp['corr']})\n";
                    $ok = false;
                }
            }
            if ($ok) {
                $pass++;
            } else {
                $fail++;
            }
        } elseif ($result === 'invalid') {
            try {
                Bodies::decode($op, $ft, $body);
                echo "  FAIL {$op} tc{$tcId}: MUST-reject vector decoded without error\n";
                $fail++;
            } catch (BodyException | CborException $e) {
                $pass++; // rejected honestly with a controlled decode error
            } catch (\Throwable $e) {
                echo "  FAIL {$op} tc{$tcId}: rejected with wrong exception type " . $e::class . ": {$e->getMessage()}\n";
                $fail++;
            }
        } else {
            echo "  FAIL {$op} tc{$tcId}: unknown result '{$result}'\n";
            $fail++;
        }
    }

    $n = count($tests);
    if ($fail === 0) {
        echo "ok   - {$op}: {$pass}/{$n} vectors graded\n";
    } else {
        echo "FAIL - {$op}: {$pass} passed, {$fail} failed of {$n}\n";
        $failedOps[] = $op;
    }
    $totalPass += $pass;
    $totalFail += $fail;
}

echo "\n";
if ($totalFail === 0) {
    echo "ALL PASS: {$totalPass} vectors across " . count($ops) . " op-groups\n";
    exit(0);
}
echo "FAILURES: {$totalFail} failed, {$totalPass} passed. Failed op-groups: " . implode(', ', $failedOps) . "\n";
exit(1);
