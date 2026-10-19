<?php

declare(strict_types=1);

namespace Tests\Security;

use OwnPay\Core\Database;
use OwnPay\Event\EventManager;
use OwnPay\Repository\LoginAttemptRepository;
use OwnPay\Repository\MerchantUserRepository;
use OwnPay\Security\Authenticator;
use PHPUnit\Framework\TestCase;

/**
 * Covers the lockout escalation contract: attempts submitted while an account
 * is already locked must count toward the window, and the exponential window
 * must stay clamped no matter how many failures accumulate.
 */
final class AccountLockoutEscalationTest extends TestCase
{
    protected function tearDown(): void
    {
        unset($_ENV['MAX_LOGIN_ATTEMPTS'], $_ENV['LOCKOUT_DURATION']);
        parent::tearDown();
    }

    /**
     * Builds a repository whose aggregate query always returns the canned row.
     *
     * @param array{fails: int, since_last: int} $row
     */
    private function repositoryReturning(array $row): LoginAttemptRepository
    {
        $db = $this->createMock(Database::class);
        $db->method('fetchOne')->willReturn($row);
        return new LoginAttemptRepository($db);
    }

    public function testLockoutWindowCountsDownWhileNoFurtherAttemptsArrive(): void
    {
        $repo = $this->repositoryReturning(['fails' => 5, 'since_last' => 120]);

        $this->assertSame(180, $repo->lockoutSecondsRemaining('victim@example.test', '203.0.113.10'));
    }

    public function testEachFailureBatchDoublesTheLockoutWindowUpToTheCap(): void
    {
        $expected = [
            5  => 300,
            10 => 600,
            15 => 1200,
            20 => 1800,
            25 => 1800,
        ];

        foreach ($expected as $fails => $window) {
            $repo = $this->repositoryReturning(['fails' => $fails, 'since_last' => 0]);
            $this->assertSame(
                $window,
                $repo->lockoutSecondsRemaining('victim@example.test', '203.0.113.10'),
                "failures={$fails} should leave {$window}s on the clock"
            );
        }
    }

    public function testSustainedFailuresNeverOverflowTheWindowIntoNoLockout(): void
    {
        // Pre-fix, 2 ** (tier - 1) overflowed the int cast at this scale and the
        // negative result slipped under the cap check, returning 0 - no lockout.
        $repo = $this->repositoryReturning(['fails' => 100000, 'since_last' => 0]);

        $this->assertSame(1800, $repo->lockoutSecondsRemaining('victim@example.test', '203.0.113.10'));
        $this->assertSame(1800, $repo->lockoutSecondsRemainingByEmail('victim@example.test', 300, 15));
    }

    public function testAttemptsSubmittedWhileLockedAreRecordedAndEscalateTheReportedWindow(): void
    {
        $_ENV['MAX_LOGIN_ATTEMPTS'] = 5;
        $_ENV['LOCKOUT_DURATION'] = 300;

        // (email, IP) counter: tier-2 window (600s) almost spent when the
        // rejected attempt arrives. The per-email counter stays below its 3x
        // threshold so the (email, IP) side alone drives the lockout here.
        $ipFails = 10;
        $ipSinceLast = 500;
        $inserted = null;

        $db = $this->createMock(Database::class);
        $db->method('fetchOne')->willReturnCallback(
            static function (string $sql) use (&$ipFails, &$ipSinceLast): array {
                if (str_contains($sql, 'ip_address = :ip')) {
                    return ['fails' => $ipFails, 'since_last' => $ipSinceLast];
                }
                return ['fails' => 4, 'since_last' => 500];
            }
        );
        $db->method('insert')->willReturnCallback(
            static function (string $sql, array $params) use (&$ipFails, &$ipSinceLast, &$inserted): string {
                $inserted = $params;
                $ipFails += 1;
                $ipSinceLast = 0;
                return '1';
            }
        );

        $auth = new Authenticator(
            new MerchantUserRepository($db),
            new LoginAttemptRepository($db),
            new EventManager()
        );

        $result = $auth->attempt('victim@example.test', 'wrong-password', '203.0.113.10', 'PHPUnit');

        $this->assertFalse($result['success']);
        $this->assertIsArray($inserted, 'an attempt made while locked must still be recorded');
        $this->assertSame('victim@example.test', $inserted['email']);
        $this->assertSame('203.0.113.10', $inserted['ip_address']);
        $this->assertSame(0, $inserted['success']);
        // The rejection reports the re-armed window (600s from the attempt just
        // recorded) rather than the near-expired remainder that preceded it.
        $this->assertStringContainsString('10 minute', (string) ($result['error'] ?? ''));
    }
}
