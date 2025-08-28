package concurrency

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type MutexManagerTestSuite struct {
	suite.Suite
	manager *MutexManager
}

func (suite *MutexManagerTestSuite) SetupTest() {
	suite.manager = NewMutexManager()
}

func (suite *MutexManagerTestSuite) TestNewMutexManager() {
	manager := NewMutexManager()

	assert.NotNil(suite.T(), manager)
	assert.NotNil(suite.T(), manager.mutexes)
	assert.Equal(suite.T(), 0, len(manager.mutexes))
}

func (suite *MutexManagerTestSuite) TestBasicLockUnlock() {
	key := "test-key"

	// Should be able to lock
	suite.manager.Lock(key)

	// Mutex should now exist in the map
	suite.manager.mapMu.RLock()
	_, exists := suite.manager.mutexes[key]
	suite.manager.mapMu.RUnlock()
	assert.True(suite.T(), exists)

	// Should be able to unlock
	suite.manager.Unlock(key)
}

func (suite *MutexManagerTestSuite) TestLockCreatesNewMutex() {
	key := "new-key"

	// Initially, mutex should not exist
	suite.manager.mapMu.RLock()
	_, exists := suite.manager.mutexes[key]
	suite.manager.mapMu.RUnlock()
	assert.False(suite.T(), exists)

	// Lock should create the mutex
	suite.manager.Lock(key)

	// Now mutex should exist
	suite.manager.mapMu.RLock()
	_, exists = suite.manager.mutexes[key]
	suite.manager.mapMu.RUnlock()
	assert.True(suite.T(), exists)

	suite.manager.Unlock(key)
}

func (suite *MutexManagerTestSuite) TestUnlockNonexistentKey() {
	key := "nonexistent-key"

	// Should not panic when unlocking a key that doesn't exist
	assert.NotPanics(suite.T(), func() {
		suite.manager.Unlock(key)
	})
}

func (suite *MutexManagerTestSuite) TestMultipleKeys() {
	keys := []string{"key1", "key2", "key3"}

	// Lock all keys
	for _, key := range keys {
		suite.manager.Lock(key)
	}

	// All mutexes should exist
	suite.manager.mapMu.RLock()
	for _, key := range keys {
		_, exists := suite.manager.mutexes[key]
		assert.True(suite.T(), exists, "Mutex should exist for key: %s", key)
	}
	suite.manager.mapMu.RUnlock()

	// Unlock all keys
	for _, key := range keys {
		suite.manager.Unlock(key)
	}
}

func (suite *MutexManagerTestSuite) TestSameKeyMultipleTimes() {
	key := "repeated-key"

	// Lock the same key multiple times in sequence
	suite.manager.Lock(key)
	suite.manager.Unlock(key)

	suite.manager.Lock(key)
	suite.manager.Unlock(key)

	suite.manager.Lock(key)
	suite.manager.Unlock(key)

	// Should still have the mutex (it doesn't get cleaned up)
	suite.manager.mapMu.RLock()
	_, exists := suite.manager.mutexes[key]
	suite.manager.mapMu.RUnlock()
	assert.True(suite.T(), exists)
}

func (suite *MutexManagerTestSuite) TestConcurrentLockCreation() {
	key := "concurrent-key"
	numGoroutines := 100
	var wg sync.WaitGroup

	// Launch multiple goroutines trying to lock the same key concurrently
	for range numGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			suite.manager.Lock(key)
			// Hold the lock briefly
			time.Sleep(1 * time.Millisecond)
			suite.manager.Unlock(key)
		}()
	}

	wg.Wait()

	// Should have created only one mutex for the key
	suite.manager.mapMu.RLock()
	_, exists := suite.manager.mutexes[key]
	count := len(suite.manager.mutexes)
	suite.manager.mapMu.RUnlock()

	assert.True(suite.T(), exists)
	assert.Equal(suite.T(), 1, count) // Only one mutex should be created
}

func (suite *MutexManagerTestSuite) TestMutualExclusion() {
	key := "exclusion-key"
	counter := 0
	numGoroutines := 50
	incrementsPerGoroutine := 100
	var wg sync.WaitGroup

	// Launch multiple goroutines that increment a counter with mutual exclusion
	for range numGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range incrementsPerGoroutine {
				suite.manager.Lock(key)
				temp := counter
				// Simulate some work that could cause race conditions
				runtime.Gosched()
				temp++
				counter = temp
				suite.manager.Unlock(key)
			}
		}()
	}

	wg.Wait()

	// Counter should equal the expected value if mutual exclusion worked
	expected := numGoroutines * incrementsPerGoroutine
	assert.Equal(suite.T(), expected, counter, "Mutual exclusion failed - race condition detected")
}

func (suite *MutexManagerTestSuite) TestDifferentKeysNoBlocking() {
	key1 := "key1"
	key2 := "key2"

	done1 := make(chan bool)
	done2 := make(chan bool)

	// Goroutine 1: Lock key1 and hold it
	go func() {
		suite.manager.Lock(key1)
		time.Sleep(100 * time.Millisecond) // Hold lock for a while
		suite.manager.Unlock(key1)
		done1 <- true
	}()

	// Goroutine 2: Lock key2 (should not be blocked by key1)
	go func() {
		time.Sleep(10 * time.Millisecond) // Small delay to ensure key1 is locked first
		suite.manager.Lock(key2)
		suite.manager.Unlock(key2)
		done2 <- true
	}()

	// Goroutine 2 should complete quickly (not blocked by key1)
	select {
	case <-done2:
		// Good - key2 was not blocked
	case <-time.After(50 * time.Millisecond):
		suite.T().Fatal("key2 was blocked by key1 - different keys should not block each other")
	}

	// Wait for goroutine 1 to complete
	<-done1
}

func (suite *MutexManagerTestSuite) TestSameKeyBlocking() {
	key := "blocking-key"

	done1 := make(chan bool)
	done2 := make(chan bool)
	startTime := time.Now()

	// Goroutine 1: Lock the key and hold it
	go func() {
		suite.manager.Lock(key)
		time.Sleep(100 * time.Millisecond) // Hold lock
		suite.manager.Unlock(key)
		done1 <- true
	}()

	// Goroutine 2: Try to lock the same key (should be blocked)
	go func() {
		time.Sleep(10 * time.Millisecond) // Ensure goroutine 1 locks first
		suite.manager.Lock(key)
		suite.manager.Unlock(key)
		done2 <- true
	}()

	// Wait for both to complete
	<-done1
	<-done2

	duration := time.Since(startTime)

	// Should have taken at least 100ms due to blocking
	assert.True(suite.T(), duration >= 100*time.Millisecond,
		"Same key should block - took %v, expected at least 100ms", duration)
}

func (suite *MutexManagerTestSuite) TestRaceConditionDetection() {
	// This test verifies that without the mutex manager, we would have race conditions
	key := "race-key"
	sharedResource := make(map[string]int)
	numGoroutines := 20
	operationsPerGoroutine := 50
	var wg sync.WaitGroup

	for i := range numGoroutines {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for range operationsPerGoroutine {
				suite.manager.Lock(key)

				// Critical section - modify shared resource
				currentValue := sharedResource["counter"]
				// Yield to potentially trigger race conditions
				runtime.Gosched()
				sharedResource["counter"] = currentValue + 1

				suite.manager.Unlock(key)
			}
		}(i)
	}

	wg.Wait()

	expected := numGoroutines * operationsPerGoroutine
	actual := sharedResource["counter"]
	assert.Equal(suite.T(), expected, actual,
		"Race condition detected: expected %d, got %d", expected, actual)
}

func (suite *MutexManagerTestSuite) TestMemoryUsage() {
	// Test that the manager doesn't leak memory excessively
	initialMapSize := len(suite.manager.mutexes)

	// Create many different locks
	numKeys := 1000
	for i := range numKeys {
		key := fmt.Sprintf("key-%d", i)
		suite.manager.Lock(key)
		suite.manager.Unlock(key)
	}

	finalMapSize := len(suite.manager.mutexes)

	// All mutexes should still exist (no cleanup mechanism in current implementation)
	assert.Equal(suite.T(), initialMapSize+numKeys, finalMapSize)
}

// Test concurrent access to the manager itself
func (suite *MutexManagerTestSuite) TestManagerConcurrency() {
	numGoroutines := 100
	operationsPerGoroutine := 10
	var wg sync.WaitGroup

	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := range operationsPerGoroutine {
				key := fmt.Sprintf("goroutine-%d-op-%d", id, j)

				// Each goroutine creates its own unique keys
				suite.manager.Lock(key)
				time.Sleep(time.Microsecond) // Brief hold
				suite.manager.Unlock(key)
			}
		}(i)
	}

	wg.Wait()

	// Should have created mutexes for all unique keys
	expectedMutexCount := numGoroutines * operationsPerGoroutine
	actualMutexCount := len(suite.manager.mutexes)

	assert.Equal(suite.T(), expectedMutexCount, actualMutexCount)
}

func TestMutexManagerTestSuite(t *testing.T) {
	suite.Run(t, new(MutexManagerTestSuite))
}

// Additional unit tests not in the suite

func TestMutexManager_EdgeCases(t *testing.T) {
	manager := NewMutexManager()

	t.Run("Empty key", func(t *testing.T) {
		// Should handle empty string keys
		assert.NotPanics(t, func() {
			manager.Lock("")
			manager.Unlock("")
		})
	})

	t.Run("Very long key", func(t *testing.T) {
		longKey := string(make([]byte, 10000)) // Very long key
		for i := range longKey {
			longKey = longKey[:i] + "a" + longKey[i+1:]
		}

		assert.NotPanics(t, func() {
			manager.Lock(longKey)
			manager.Unlock(longKey)
		})
	})

	t.Run("Unicode keys", func(t *testing.T) {
		unicodeKey := "测试-🔒-мютекс"

		assert.NotPanics(t, func() {
			manager.Lock(unicodeKey)
			manager.Unlock(unicodeKey)
		})
	})
}

func TestMutexManager_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	manager := NewMutexManager()
	numGoroutines := 1000
	duration := 2 * time.Second
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Start stress test
	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for {
				select {
				case <-stop:
					return
				default:
					key := fmt.Sprintf("stress-key-%d", id%10) // Reuse some keys
					manager.Lock(key)
					time.Sleep(time.Microsecond)
					manager.Unlock(key)
				}
			}
		}(i)
	}

	// Run for specified duration
	time.Sleep(duration)
	close(stop)
	wg.Wait()

	// Should not have panicked and should have some mutexes created
	assert.True(t, len(manager.mutexes) > 0)
	assert.True(t, len(manager.mutexes) <= 10) // At most 10 different keys
}

func TestMutexManager_DeadlockPrevention(t *testing.T) {
	manager := NewMutexManager()

	// Test that using the same MutexManager from different goroutines
	// with different keys doesn't cause deadlocks
	done := make(chan struct{}, 2)

	go func() {
		for range 100 {
			manager.Lock("key-a")
			time.Sleep(time.Microsecond)
			manager.Lock("key-b")
			manager.Unlock("key-b")
			manager.Unlock("key-a")
		}
		done <- struct{}{}
	}()

	go func() {
		for range 100 {
			manager.Lock("key-c")
			time.Sleep(time.Microsecond)
			manager.Lock("key-d")
			manager.Unlock("key-d")
			manager.Unlock("key-c")
		}
		done <- struct{}{}
	}()

	// Should complete without deadlock
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	for range 2 {
		select {
		case <-done:
			// Good, no deadlock
		case <-timer.C:
			t.Fatal("Potential deadlock detected - test timed out")
		}
	}
}

// Benchmark tests
func BenchmarkMutexManager_LockUnlock(b *testing.B) {
	manager := NewMutexManager()
	key := "benchmark-key"

	for b.Loop() {
		manager.Lock(key)
		manager.Unlock(key)
	}
}

func BenchmarkMutexManager_MultipleLocks(b *testing.B) {
	manager := NewMutexManager()
	keys := make([]string, 100)
	for i := range keys {
		keys[i] = fmt.Sprintf("bench-key-%d", i)
	}

	for i := 0; b.Loop(); i++ {
		key := keys[i%len(keys)]
		manager.Lock(key)
		manager.Unlock(key)
	}
}

func BenchmarkMutexManager_ConcurrentAccess(b *testing.B) {
	manager := NewMutexManager()
	key := "concurrent-bench-key"

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			manager.Lock(key)
			manager.Unlock(key)
		}
	})
}
