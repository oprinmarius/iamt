package internal

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
)

func TestSelectNextState_When_NoneOfTheRequestedStatesAreAvailable_Expect_Unknown(t *testing.T) {
	availableStates := []powerState{stateOn}
	nextState := selectNextState(getPowerOffStates(), availableStates)
	assert.Equal(t, unknown, nextState)
}

func TestSelectNextState_When_OneOfTheRequestedStatesAreAvailable_Expect_RequestedState(t *testing.T) {
	requestedStates := getPowerOffStates()
	availableStates := []powerState{requestedStates[0]}
	nextState := selectNextState(requestedStates, availableStates)
	assert.Equal(t, requestedStates[0], nextState)
}

func TestSelectNextState_When_MultipleOfTheRequestedStatesAreAvailable_Expect_FirstAvailableRequestedState(t *testing.T) {
	requestedStates := getPowerOffStates()
	availableStates := []powerState{requestedStates[1], requestedStates[2]}
	nextState := selectNextState(requestedStates, availableStates)
	assert.Equal(t, requestedStates[1], nextState)
}

func TestIsPoweredOnGivenStatus_When_powerStateOn_Expect_True(t *testing.T) {
	status := &powerStatus{powerState: stateOn}
	actual := isPoweredOnGivenStatus(logr.Discard(), status)
	assert.Equal(t, true, actual)
}

func TestIsPoweredOnGivenStatus_When_powerStateOffSoft_Expect_False(t *testing.T) {
	status := &powerStatus{powerState: offSoft}
	actual := isPoweredOnGivenStatus(logr.Discard(), status)
	assert.Equal(t, false, actual)
}

func TestContainsPowerState_When_StateIsPresent_Expect_True(t *testing.T) {
	states := []powerState{stateOn, offSoft, offHard}
	assert.True(t, containspowerState(states, offSoft))
}

func TestContainsPowerState_When_StateIsNotPresent_Expect_False(t *testing.T) {
	states := []powerState{stateOn, offSoft, offHard}
	assert.False(t, containspowerState(states, hibernateOffSoft))
}

func TestContainsPowerState_When_EmptySlice_Expect_False(t *testing.T) {
	states := []powerState{}
	assert.False(t, containspowerState(states, stateOn))
}

func TestGetPowerOffStates_Returns_ExpectedStates(t *testing.T) {
	states := getPowerOffStates()
	assert.Len(t, states, 4)
	assert.Contains(t, states, offSoftGraceful)
	assert.Contains(t, states, offSoft)
	assert.Contains(t, states, offHardGraceful)
	assert.Contains(t, states, offHard)
}

func TestGetPowerCycleStates_Returns_ExpectedStates(t *testing.T) {
	states := getPowerCycleStates()
	assert.Len(t, states, 6)
	assert.Contains(t, states, powerCycleOffSoftGraceful)
	assert.Contains(t, states, powerCycleOffSoft)
	assert.Contains(t, states, masterBusResetGraceful)
	assert.Contains(t, states, powerCycleOffHardGraceful)
	assert.Contains(t, states, powerCycleOffHard)
	assert.Contains(t, states, masterBusReset)
}

func TestIsPoweredOnGivenStatus_AllOffStates_ReturnFalse(t *testing.T) {
	offStates := []powerState{
		unknown, other, sleepLight, sleepDeep, powerCycleOffSoft,
		offHard, hibernateOffSoft, offSoft, powerCycleOffHard,
		masterBusReset, diagnosticInterruptNMI, offSoftGraceful,
		offHardGraceful, masterBusResetGraceful, powerCycleOffSoftGraceful,
		powerCycleOffHardGraceful, diagnosticInterruptInit,
	}
	for _, state := range offStates {
		status := &powerStatus{powerState: state}
		actual := isPoweredOnGivenStatus(logr.Discard(), status)
		assert.False(t, actual, "expected state %v to be considered off", state)
	}
}
