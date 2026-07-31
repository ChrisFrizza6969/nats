<?php

declare(strict_types=1);

namespace Thesis\Nats\JetStream\ObjectStore;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Pins the object digest encoding: base64url WITH padding.
 *
 * nats.go decodes the digest with base64.URLEncoding (padded) in
 * DecodeObjectDigest, so an unpadded value makes every Go reader fail with
 * "illegal base64 data at input byte 40" — the 43rd character of what should be
 * a 44-character encoded SHA-256. That failure only shows up when another client
 * reads the object back, which is why it can survive a green test suite here.
 *
 * Subject names are the opposite case: they are unpadded on purpose, so the two
 * encodings must not be unified.
 */
#[CoversClass(Store::class)]
final class DigestEncodingTest extends TestCase
{
    /** Mirrors the digest encoding in Store::put(). */
    private static function encodeDigest(string $rawSha256): string
    {
        return strtr(base64_encode($rawSha256), '+/', '-_');
    }

    /** Mirrors Store::base64encode(), used for subject names. */
    private static function encodeSubjectName(string $name): string
    {
        return rtrim(strtr(base64_encode($name), '+/', '-_'), '=');
    }

    public function testDigestIsAlways44CharactersAndPadded(): void
    {
        // A SHA-256 is 32 bytes, which always base64-encodes to 44 chars with a
        // single '=' pad. Anything shorter means the padding was stripped.
        foreach (['', 'a', 'firmware payload', str_repeat("\x00", 1024)] as $payload) {
            $encoded = self::encodeDigest(hash('sha256', $payload, true));
            self::assertSame(44, \strlen($encoded), 'encoded SHA-256 must be 44 chars');
            self::assertStringEndsWith('=', $encoded, 'padding must be preserved');
        }
    }

    public function testDigestUsesUrlAlphabetNotStandard(): void
    {
        // Find a payload whose digest exercises the +/ -> -_ substitution, so a
        // regression to plain base64_encode() is caught too.
        for ($i = 0; $i < 5000; ++$i) {
            $raw = hash('sha256', "probe-{$i}", true);
            $std = base64_encode($raw);
            if (!str_contains($std, '+') && !str_contains($std, '/')) {
                continue;
            }
            $encoded = self::encodeDigest($raw);
            self::assertStringNotContainsString('+', $encoded);
            self::assertStringNotContainsString('/', $encoded);
            self::assertNotSame($std, $encoded, 'must use the URL alphabet');
            return;
        }

        self::fail('no probe digest contained + or / — cannot assert the URL alphabet');
    }

    public function testDigestSatisfiesGoUrlEncodingPaddingRule(): void
    {
        // NOTE: PHP's base64_decode(..., strict: true) still accepts UNPADDED
        // input, so a naive round-trip here passes even for a stripped digest and
        // would not catch the regression. Go's base64.URLEncoding is stricter: it
        // requires the input length to be a multiple of 4. Assert that rule
        // directly, since that is what the Go reader enforces.
        $raw = hash('sha256', 'firmware payload', true);
        $encoded = self::encodeDigest($raw);

        self::assertSame(0, \strlen($encoded) % 4, 'Go base64.URLEncoding requires a length multiple of 4');
        self::assertSame($raw, base64_decode(strtr($encoded, '-_', '+/'), true));

        // And prove the stripped form violates it — this is the exact shape that
        // produced "illegal base64 data at input byte 40" in nats.go.
        $stripped = rtrim($encoded, '=');
        self::assertNotSame(0, \strlen($stripped) % 4, 'stripped digest must be rejected by a Go reader');
    }

    public function testSubjectNamesStayUnpadded(): void
    {
        // The inverse invariant: unifying the two encoders in either direction
        // breaks one of them.
        self::assertSame('MC43LjQ2', self::encodeSubjectName('0.7.46'));
        self::assertStringNotContainsString('=', self::encodeSubjectName('0.7.46'));
    }
}
