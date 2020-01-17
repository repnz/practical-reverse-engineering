/*
	Code that fetches information about the DpcData queues.
	I tried to do it as reliable as possible - I would not say it's "reliable" but I think there are enough checks
	to prevent blue screens - although I cannot promise this.

	The data structures were changed a bit in windows 8.1, we have to handle this.

	The general algorithm is:

	- Validate that the layout of the DPC object is as expected by creating a DPC and 
	  checking the values of it's members.

	- Fetch the DpcData member by assuming that this is the layout of the structure:

struct _KPRCB {
	...
	...
	...
	struct _KDPC_DATA DpcData[2];
	VOID* DpcStack;                                                         
	...
	...
}

	The DpcStack member is right after the DpcData member. If the offset of DpcStack can be found,
	it can be used to find the DpcData member. Of course, this assumption is validated.

	The offset of the DpcStack member is found by queueing a DPC. When the DPC routine runs the value of RSP is taken
	from this member. This is true only in the context of a DPC interrupt. If the idle thread runs the DPC routine, the value of RSP 
	is not changed - So we have to make sure the DPC is run in the context of a DPC interrupt. We do this by queuing the DPC from PASSIVE_LEVEL
	with HighImportance. So we take the value of RSP, search in the KPRCB, and find the DpcData.

	
	- After the KDPC_DATA was found, trigger an inter-processor interrupt that will validate the contents of the KDPC_DATA structure.
	  An IPI is used to prevent other CPUs from changing the queue.



*/
#include "DpcDataSignature.h"

//
// Build numbers
//
#define WIN_8 9200
#define WIN_8_1 9600


//
// Magic constants used in the DPC arguments
//
#define DeferredContextMagic 0x12345678
#define SystemArgument1Magic 0xabcdef21
#define SystemArgument2Magic 0x21436586



//
// Macros used to access memory 
//
#define OFFSET_PTR(ptr, offset) \
	((PVOID)(((ULONG_PTR)(ptr)) + ((ULONG_PTR)(offset))))

#define READ_OFFSET_ULONG_PTR(ptr, offset) \
	(*(ULONG_PTR*)OFFSET_PTR(ptr, offset))



//
// Enum of windows kernel object types.
// The enum has more members but we only care about Dpc.
// ThreadedDpcObject is also a member but it's value was changed in 8.1...
//
typedef enum _KOBJECTS {
	DpcObject = 19
} KOBJECTS;

//
// This is a structure that describes the common elements in KDPC_DATA before and after 
// it was changed in 8.1.
//
typedef struct _SHARED_KDPC_DATA {
	SINGLE_LIST_ENTRY ListHead;
	SINGLE_LIST_ENTRY LastEntry;
	KSPIN_LOCK DpcLock;
	LONG DpcQueueDepth;
	ULONG DpcCount;
} SHARED_KDPC_DATA, * PSHARED_KDPC_DATA;

//
// This is Prcb.DpcData in < 8.1
//
typedef struct _KDPC_DATA_1 {
	LIST_ENTRY DpcListHead; // Practically pointer to the ListHead and LastEntry..
	KSPIN_LOCK DpcLock;
	LONG DpcQueueDepth;
	ULONG DpcCount;
} KDPC_DATA_1, * PKDPC_DATA_1;


//
// This structure only exists in >= 8.1.
//
typedef struct _KDPC_LIST {
	SINGLE_LIST_ENTRY ListHead;
	PSINGLE_LIST_ENTRY LastEntry;
} KDPC_LIST, * PKDPC_LIST;


//
// This is Prcb.DpcData in >= 8.1
//
typedef struct _KDPC_DATA_2 {
	KDPC_LIST DpcList;
	KSPIN_LOCK DpcLock;
	LONG DpcQueueDepth;
	ULONG DpcCount;
	PKDPC ActiveDpc;
} KDPC_DATA_2, * PKDPC_DATA_2;


//
// This is a global structure that contains information
// about the signature
//
typedef struct _DPC_SIGNATURE_INFO {
	//
	// This flag is set to TRUE if the signature failed.
	//
	BOOLEAN SignatureFailed;

	//
	// The offsets of relevant members inside the PCR
	//
	ULONG PcrDpcStackOffset;
	ULONG PcrDpcDataOffset;

	//
	// A flag indicating if the build version is >= 8.1
	//
	BOOLEAN IsNewVersion;
	ULONG NtBuildNumber;

	//
	// The value of Rsp inside the DPC routine
	//
	ULONG_PTR DpcRspValue;
	

	//
	// The size of the KDPC_DATA structure. May be different between versions
	//
	ULONG DpcDataSize;
	
	//
	// Pointers to the PCR data structure on all of the processors
	//
	PKPCR ProcessorPcr[16];

	//
	// The number of processors 
	//
	CCHAR NumberOfProcessors;

} DPC_SIGNATURE_INFO, * PDPC_SIGNATURE_INFO;


static DPC_SIGNATURE_INFO gSigInfo;

//
// A function implemented in assembly to fetch the value of RSP right now
//
extern ULONG_PTR inline GetRsp();


VOID
SignatureDpcRoutine(
	__in PKDPC Dpc,
	__in_opt PVOID DeferredContext,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2
);


ULONG_PTR
SignatureVerificationIpiRoutine(
	__in ULONG_PTR Context
	);

PSHARED_KDPC_DATA
GetCurrentDpcData(
	VOID
);


VOID
NullDpcRoutine(
	__in PKDPC Dpc,
	__in_opt PVOID DeferredContext,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2
)
/*++
	
	A pointer to a routine that should not run at all. 
	Used while creating temporary DPC objects.

--*/
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
		
	gSigInfo.SignatureFailed = TRUE;
}

BOOLEAN
ValidateDpcType(
	VOID
);

BOOLEAN
ValidateDpcImportance(
	VOID
);

BOOLEAN
ValidateDpcListHead(
	PKDPC_DATA_2 DpcData
	);


NTSTATUS
InitializeDpcSignature(
	VOID
)
{
	
	RtlZeroMemory(&gSigInfo, sizeof(gSigInfo));

	gSigInfo.NumberOfProcessors = KeNumberProcessors;
	
	//
	// Get the build number
	//
	UNICODE_STRING NtBuildNumber = RTL_CONSTANT_STRING(L"NtBuildNumber");
	PUSHORT NtBuildNumberAddress = MmGetSystemRoutineAddress(&NtBuildNumber);

	if (NtBuildNumberAddress == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	gSigInfo.NtBuildNumber = *(PUSHORT)NtBuildNumberAddress;

	if (gSigInfo.NtBuildNumber < 7600) {
		return STATUS_UNSUCCESSFUL;
	}

	if (!ValidateDpcType()) {
		return FALSE;
	}

	if (!ValidateDpcImportance()) {
		return FALSE;
	}

	//
	// Insert a DPC structure to the queue.
	// This will run the DPC routine. 
	//
	KDPC Dpc;

	KeInitializeDpc(&Dpc, &SignatureDpcRoutine, (PVOID)0x12345678);
	KeSetImportanceDpc(&Dpc, HighImportance);

	//
	// The InsertQueueDpc call should cause an interrupt that will schedule the DPC
	//
	KeInsertQueueDpc(&Dpc, (PVOID)0xabcdef21, (PVOID)0x21436586);

	//
	// Because the code here continues only when the interrupt ends, 
	// the DPC should not be in the queue. Use KeRemoveQueueDpcEx to remove the DPC from the queue
	// or wait until it finishes.
	//
	KeRemoveQueueDpcEx(&Dpc, TRUE);

	if (gSigInfo.SignatureFailed) {
		return FALSE;
	}

	//
	// Trigger an IPI that will validate the DPC_DATA structure. 
	// The call will return from KeIpiGenericCall only when the IPI finishes.
	//
	KeIpiGenericCall(&SignatureVerificationIpiRoutine, 0);

	if (gSigInfo.SignatureFailed) {
		return FALSE;
	}

	return TRUE;
}

BOOLEAN
ValidateDpcListHead(
	PKDPC_DATA_2 DpcData
)
{
	KDPC Dpc;
	
	KeInitializeDpc(&Dpc, &NullDpcRoutine, NULL);
	KeSetImportanceDpc(&Dpc, HighImportance);

	ULONG OldDpcCount = DpcData->DpcCount;
	LONG OldDpcDepth = DpcData->DpcQueueDepth;
	PVOID OldHead = DpcData->DpcList.ListHead.Next;
	PVOID OldLastEntry = DpcData->DpcList.LastEntry;

	//
	// If the queue is empty, The Head should be NULL and the LastEntry should point to the first entry.
	//
	if (OldDpcDepth == 0 && ((OldHead != NULL) || (OldLastEntry != &DpcData->DpcList.ListHead.Next))) {
		return FALSE;
	}

	KeInsertQueueDpc(&Dpc, NULL, NULL);
	
	if (

		//
		// The DpcCount and DpcQueueDepth members should be increased by one
		//
		(DpcData->DpcCount != (OldDpcCount + 1)) ||
		(DpcData->DpcQueueDepth != (OldDpcDepth + 1)) || 
		
		//
		// If the list has more than one element, the LastEntry member should not change.
		//
		(DpcData->DpcQueueDepth > 1 && (DpcData->DpcList.LastEntry != OldLastEntry)) ||

		//
		// If the queue has one member, the LastEntry should be equal to the DpcListEntry of the member
		//
		(DpcData->DpcQueueDepth == 1 && (DpcData->DpcList.LastEntry != &Dpc.DpcListEntry)) ||


		//
		// The head of the list should point to the new member
		//
		(DpcData->DpcList.ListHead.Next != &Dpc.DpcListEntry) || 
		
		//
		// The next of the new DpcListEntry should be the OldHead.
		//
		(Dpc.DpcListEntry.Next != OldHead)
		
		) {

		KeRemoveQueueDpc(&Dpc);
		return FALSE;
	}

	KeRemoveQueueDpc(&Dpc);

	if (
		//
		// The DpcCount member should stay (Old+1), event if the item was removed
		//
		(DpcData->DpcCount != (OldDpcCount + 1)) ||

		//
		// The DpcQueueDepth should be decreased by one.
		//
		(DpcData->DpcQueueDepth != OldDpcDepth) ||

		//
		// The Head of the list should return to it's original value
		//
		(DpcData->DpcList.ListHead.Next != OldHead) || 

		//
		// The LastEntry should return to it's original value
		//
		(DpcData->DpcList.LastEntry != OldLastEntry)

		) {
		return FALSE;
	}

	return TRUE;
}



BOOLEAN
ValidateDpcListLastEntry(
	PKDPC_DATA_2 DpcData
)
{
	KDPC Dpc;

	KeInitializeDpc(&Dpc, &NullDpcRoutine, NULL);
	KeSetImportanceDpc(&Dpc, LowImportance);

	ULONG OldDpcCount = DpcData->DpcCount;
	LONG OldDpcDepth = DpcData->DpcQueueDepth;
	PVOID OldHead = DpcData->DpcList.ListHead.Next;
	PVOID OldLastEntry = DpcData->DpcList.LastEntry;

	
	KeInsertQueueDpc(&Dpc, NULL, NULL);

	if (

		//
		// The DpcCount and DpcQueueDepth members should be increased by one
		//
		(DpcData->DpcCount != (OldDpcCount + 1)) ||
		(DpcData->DpcQueueDepth != (OldDpcDepth + 1)) ||

		//
		// If the list has more than one element, the ListHead member should not change.
		//
		(DpcData->DpcQueueDepth > 1 && (DpcData->DpcList.ListHead.Next != OldHead)) ||

		//
		// If the queue has one member, the ListHead should be equal to the DpcListEntry of the member
		//
		(DpcData->DpcQueueDepth == 1 && (DpcData->DpcList.ListHead.Next != &Dpc.DpcListEntry)) ||

		//
		// The tail of the list should point to the new member
		//
		(DpcData->DpcList.LastEntry != &Dpc.DpcListEntry) ||

		//
		// The next of the new DpcListEntry should be NULL
		//
		(Dpc.DpcListEntry.Next != NULL)

		) {

		KeRemoveQueueDpc(&Dpc);
		return FALSE;
	}

	KeRemoveQueueDpc(&Dpc);

	if (
		//
		// The DpcCount member should stay (Old+1), event if the item was removed
		//
		(DpcData->DpcCount != (OldDpcCount + 1)) ||

		//
		// The DpcQueueDepth should be decreased by one.
		//
		(DpcData->DpcQueueDepth != OldDpcDepth) ||

		//
		// The Head of the list should return it's original value
		//
		(DpcData->DpcList.ListHead.Next != OldHead) || 

		//
		// The LastEntry of the list should return it's original value
		//
		(DpcData->DpcList.LastEntry != OldLastEntry)

		) {
		return FALSE;
	}

	return TRUE;
}


//
// This routine runs at HIGH IRQL. Be careful
//
//
BOOLEAN
ValidateDpcListNew(
	PKDPC_DATA_2 DpcData
)
{
	return ValidateDpcListHead(DpcData) && 
			ValidateDpcListLastEntry(DpcData);
}

BOOLEAN ValidateDpcDataList(
	PSHARED_KDPC_DATA DpcData
)
{
	return ValidateDpcListNew((PKDPC_DATA_2)DpcData);
}


BOOLEAN
FetchDpcDataOffset(
	PKDPC ActiveDpc
)
{
	//
	// The trick is to find the DpcStack member of the _KPRCB and then look above.
	// This DPC routine was queued in context of the PASSIVE_LEVEL DriverEntry() caller so we can assume the 
	// stack will be a DPC stack (and not the ki!IdleThread stack..)
	//
	PKPCR PcrAddress = KeGetPcr();

	//
	// Validate the KPCR is valid..
	//
	if (!PcrAddress || PcrAddress->CurrentPrcb != OFFSET_PTR(PcrAddress, 0x180)) {
		return FALSE;
	}

	gSigInfo.PcrDpcStackOffset = 0;

	//
	// Look for the DpcStack member..
	//
	for (ULONG Offset = 0x180; Offset < 0x4900; Offset += 8) {

		ULONG_PTR DpcStack = READ_OFFSET_ULONG_PTR(PcrAddress, Offset);

		//
		// The stack grows down.
		//
		if (DpcStack <= gSigInfo.DpcRspValue) {
			continue;
		}

		//
		// If the diff is bigger than one page, it means this value is not the DpcStack.
		//
		if ((DpcStack - gSigInfo.DpcRspValue) <= 0x1000) {
			gSigInfo.PcrDpcStackOffset = Offset;
			break;
		}
	}

	if (!gSigInfo.PcrDpcStackOffset) {
		return FALSE;
	}

	//
	// Find the offset of the DpcData in newer builds of windows
	//
	ULONG NewDpcDataOffset = gSigInfo.PcrDpcStackOffset - (sizeof(KDPC_DATA_2) * 2);

	//
	// Check if the ActiveDpc pointer is there.
	//
	PKDPC_DATA_2 DpcData2 = (PKDPC_DATA_2)OFFSET_PTR(PcrAddress, NewDpcDataOffset);

	//
	// The ActiveDpc member exists only in the new version
	//
	if (DpcData2->ActiveDpc == ActiveDpc) {
		gSigInfo.PcrDpcDataOffset = NewDpcDataOffset;
		gSigInfo.DpcDataSize = sizeof(KDPC_DATA_2);
		gSigInfo.IsNewVersion = TRUE;
	}
	else {
		gSigInfo.PcrDpcDataOffset = gSigInfo.PcrDpcStackOffset - (sizeof(KDPC_DATA_1) * 2);
		gSigInfo.DpcDataSize = sizeof(KDPC_DATA_1);
		gSigInfo.IsNewVersion = FALSE;
	}

	//
	// the refactor was in windows 8, check that things aren't weird
	//

	if (gSigInfo.IsNewVersion && gSigInfo.NtBuildNumber <= WIN_8) {
		return FALSE;
	}
	else if (!gSigInfo.IsNewVersion && gSigInfo.NtBuildNumber > WIN_8_1) {
		return FALSE;
	}


	PVOID DpcData = OFFSET_PTR(PcrAddress, gSigInfo.PcrDpcDataOffset);

	//
	// In the older version we had another source of information.. 
	// In the newer version we had ActiveDpc
	// There's an additional validation later..
	//
	if (!gSigInfo.IsNewVersion && DpcData != ActiveDpc->DpcData) {
		return FALSE;
	}

	return TRUE;

}

VOID
SignatureDpcRoutine(
	__in PKDPC Dpc,
	__in_opt PVOID DeferredContext,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2
)
{
	BOOLEAN SignatureFailed = TRUE;

	//
	// We'll need it later to get KPCR.Prcb.DpcStack
	//
	gSigInfo.DpcRspValue = GetRsp();

	//
	// Sanity Checks to see the DPC object was not changed..
	//
	//
	if (Dpc->DeferredContext != DeferredContext) {
		goto cleanup;
	}

	if (Dpc->DeferredRoutine != &SignatureDpcRoutine) {
		goto cleanup;
	}

	if (Dpc->SystemArgument1 != SystemArgument1) {
		goto cleanup;
	}

	if (Dpc->SystemArgument2 != SystemArgument2) {
		goto cleanup;
	}

	if (!FetchDpcDataOffset(Dpc)) {
		goto cleanup;
	}

	SignatureFailed = FALSE;

cleanup:
	gSigInfo.SignatureFailed = SignatureFailed;
}

BOOLEAN
ValidateDpcType(
	VOID
)
/*++
	Validate the KDPC.Type member of the DPC structure.
*/
{
	KDPC Dpc;

	KeInitializeDpc(&Dpc, &NullDpcRoutine, NULL);

	if (Dpc.Type != DpcObject) {
		DbgPrint("Could not find KDPC.Type");
		return FALSE;
	}

	return TRUE;
}

BOOLEAN
ValidateDpcImportance(
	VOID
)
/*++

	Validate the DPC.Importance member.
	The validation is done by creating a DPC object, changing the Importance property
	and checking if the member was changed as expected.

--*/
{

	KDPC Dpc;

	//
	// Initialize the DPC object to MediumImportance
	//
	KeInitializeDpc(&Dpc, &NullDpcRoutine, NULL);
	KeSetImportanceDpc(&Dpc, MediumImportance);


	if (Dpc.Importance != MediumImportance) {
		DbgPrint("Error Finding KDPC.Importance");
		return FALSE;
	}

	//
	// Replace the importance and validate the member has changed
	//
	KeSetImportanceDpc(&Dpc, HighImportance);

	if (Dpc.Importance != HighImportance) {
		DbgPrint("Error Finding KDPC.Importance");
		return FALSE;
	}

	return TRUE;
}

PSHARED_KDPC_DATA 
GetDpcData(
	ULONG ProcessorIndex
	) 
{
	PKPCR PcrAddress = gSigInfo.ProcessorPcr[ProcessorIndex];
	return (PSHARED_KDPC_DATA)OFFSET_PTR(PcrAddress, gSigInfo.PcrDpcDataOffset);
}

ULONG
GetCurrentProcessorIndex(
	VOID
	)
{
	PROCESSOR_NUMBER ProcessorNumber;
	KeGetCurrentProcessorNumberEx(&ProcessorNumber);
	return KeGetProcessorIndexFromNumber(&ProcessorNumber);
}


ULONG_PTR
SignatureVerificationIpiRoutine(
	__in ULONG_PTR Context
	)
/*++
	
	We trigger an IPI to validate the contents of the queue.
	We cannot simply take the spin lock because we call functions like KeInsertQueueDpc, 
	these functions will try to acquire the spin lock and it will cause a deadlock. (Spin locks
	cannot be acquired twice from the same CPU)

--*/
{
	
	UNREFERENCED_PARAMETER(Context);

	KIRQL OldIrql;

	//
	// Raise the IRQL to the highest to prevent preemption
	//
	KeRaiseIrql(HIGH_LEVEL, &OldIrql);

	//
	// Save the address of the CPU
	//
	PKPCR PcrAddress = KeGetPcr();
	ULONG ProcessorIndex =  GetCurrentProcessorIndex();
	gSigInfo.ProcessorPcr[ProcessorIndex] = PcrAddress;

	PSHARED_KDPC_DATA DpcData = (PSHARED_KDPC_DATA)OFFSET_PTR(PcrAddress, gSigInfo.PcrDpcDataOffset);

	if (!ValidateDpcDataList(DpcData)) {
		gSigInfo.SignatureFailed = TRUE;
	}

	KeLowerIrql(OldIrql);
	return 0;
}

PDPC_QUEUE
DpcDataToDpcQueue(
	PSHARED_KDPC_DATA DpcData
	)
{
	LONG DpcDepth;
	KIRQL OldIrql;
	PDPC_QUEUE NewQueue = NULL;
	
	//
	// Allocate the DpcQueue, raise to IRQL and acquire the lock
	// The problem is: we cannot allocate memory at HIGH_IRQL and the lock has to be acquired at
	// HIGH_IRQL, so we have to:
	//
	// 1) Allocate the memory for the queue
	// 2) Acquire the lock
	// 3) Test that the depth of the queue wasn't changed between the memory allocation and now (can be caused by an interrupt..)
	//		- If the queue was changed, release the lock and try again.
	//		- If the queue was not changed, keep the lock and continue.
	//
	for (ULONG i = 0; i < 5; i++) {

		DpcDepth = DpcData->DpcQueueDepth;
		ULONG NewQueueSize = sizeof(DPC_QUEUE) + (sizeof(DPC_OBJECT) * DpcDepth);
		NewQueue = ExAllocatePoolWithTag(NonPagedPool, NewQueueSize, 'qcpD');

		if (!NewQueue) {
			return NULL;
		}
		
		RtlZeroMemory(NewQueue, NewQueueSize);

		KeRaiseIrql(HIGH_LEVEL, &OldIrql);
		KeAcquireSpinLockAtDpcLevel(&DpcData->DpcLock);

		if (DpcData->DpcQueueDepth == DpcDepth) {
			//
			// The size stayed the same! continue
			//
			break;
		}

		//
		// The size was changed? 
		// Try again.
		//
		KeReleaseSpinLockFromDpcLevel(&DpcData->DpcLock);
		KeLowerIrql(OldIrql);
		ExFreePool(NewQueue);
	}

	if (!NewQueue) {
		return NULL;
	}
	
	NewQueue->DpcDataPtr = DpcData;
	NewQueue->DpcCount = DpcData->DpcCount;
	NewQueue->DpcQueueDepth = DpcData->DpcQueueDepth;
	
	//
	// Go over the DPC queue and copy the DPC information into the output buffer
	//
	PKDPC CurrentDpc = CONTAINING_RECORD(DpcData->ListHead.Next, KDPC, DpcListEntry);

	for (LONG i = 0; i < DpcDepth; i++) {
		NewQueue->DpcObjects[i].OriginalDpcPtr = CurrentDpc;
		RtlCopyMemory(&NewQueue->DpcObjects[i].DpcCopy, CurrentDpc, sizeof(KDPC));

		if (CurrentDpc->DpcListEntry.Next == NULL) {
			break;
		}

		CurrentDpc = CONTAINING_RECORD((CurrentDpc->DpcListEntry.Next), KDPC, DpcListEntry);
	}

	KeReleaseSpinLockFromDpcLevel(&DpcData->DpcLock);
	KeLowerIrql(OldIrql);
	return NewQueue;
}

NTSTATUS
GetDpcInformation(
	__out PDPC_INFORMATION DpcInformation
	)
/*++
	Go over all the queues of the CPUs and dump the DPC objects
--*/
{
	RtlZeroMemory(DpcInformation, sizeof(DPC_INFORMATION));

	ULONG SizeOfDpcQueues = sizeof(PDPC_QUEUE) * gSigInfo.NumberOfProcessors;
	DpcInformation->DpcQueues = ExAllocatePoolWithTag(NonPagedPool, sizeof(PDPC_QUEUE) * gSigInfo.NumberOfProcessors, 'qcpD');

	if (!DpcInformation->DpcQueues) {
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(DpcInformation->DpcQueues, SizeOfDpcQueues);
	DpcInformation->QueueCount = gSigInfo.NumberOfProcessors;

	for (int i = 0; i < gSigInfo.NumberOfProcessors; i++) {
		
		PSHARED_KDPC_DATA DpcData = GetDpcData(i);
		PDPC_QUEUE DpcQueue = DpcDataToDpcQueue(DpcData);
		DpcQueue->ProcessorNumber = i;
		
		if (!DpcQueue) {
			//
			// If the DpcQueue could not be fetched, 
			// free all the queues and exit.
			//
			for (int j = 0; j < i; j++) {
				ExFreePool(DpcInformation->DpcQueues[j]);
			}

			//
			// Free the list of queues
			//
			ExFreePool(DpcInformation->DpcQueues);
			return STATUS_UNSUCCESSFUL;
		}

		DpcInformation->DpcQueues[i] = DpcQueue;
		DpcInformation->TotalDpcQueueDepth += DpcQueue->DpcQueueDepth;
	}

	return STATUS_SUCCESS;
}

VOID
FreeDpcInformation(
	__in PDPC_INFORMATION Information
	) 
{
	if (!Information->DpcQueues) {
		return;
	}

	for (ULONG i = 0; i < Information->QueueCount; i++) {
		if (Information->DpcQueues[i]) {
			ExFreePool(Information->DpcQueues[i]);
		}

	}

	ExFreePool(Information->DpcQueues);
}