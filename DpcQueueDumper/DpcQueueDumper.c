/*
	This code implements the DpcQueueDumper.
*/
#include <ntifs.h>
#include <ntddk.h>
#include "DpcDataSignature.h"

VOID
PrintDpcInformation(
	PDPC_INFORMATION DpcInformation
	);


VOID
MyDpcRoutine(
	__in PKDPC ActiveDpc,
	__in_opt PVOID DeferredContext,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2
) 
{
	UNREFERENCED_PARAMETER(ActiveDpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	DbgPrint("MyDpcRoutine!");
}

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryKey
	) 
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryKey);

	NTSTATUS Status;

	Status = InitializeDpcSignature();

	if (!NT_SUCCESS(Status)) {
		return STATUS_UNSUCCESSFUL;
	}

	//
	// Raise the IRQL to DISPATCH_LEVEL
	// This is done because we want the DPC to stay in the queue
	//
	KIRQL OldIrql = KeRaiseIrqlToDpcLevel();

	DPC_INFORMATION DpcInformation;
	KDPC LowDpc;
	
	//
	// Put a DPC object in the queue
	//
	KeInitializeDpc(&LowDpc, MyDpcRoutine, NULL);
	KeSetImportanceDpc(&LowDpc, LowImportance);
	KeInsertQueueDpc(&LowDpc, NULL, NULL);


	//
	// Get the dump of the queues of DPC objects
	//
	Status = GetDpcInformation(&DpcInformation);

	if (!NT_SUCCESS(Status)) {
		return STATUS_UNSUCCESSFUL;
	}

	//
	// Return to PASSIVE_LEVEL. 
	// This will cause the DPC to execute.
	//
	KeLowerIrql(OldIrql);

	//
	// Print the DPC information
	//
	PrintDpcInformation(&DpcInformation);
	
	FreeDpcInformation(&DpcInformation);
	
	KeRemoveQueueDpcEx(&LowDpc, TRUE);

	return STATUS_UNSUCCESSFUL;
}


PCSTR
DpcTypeToString(
	ULONG DpcType
	)
{
	if (DpcType == 19) {
		return "DpcObject";
	}
	else if (DpcType == 24) {
		return "ThreadedDpcObject";
	}
	else if (DpcType == 26) {
		return "ThreadedDpcObject";
	}

	return "InvalidType";
}


PCSTR
DpcImportanceToString(
	KDPC_IMPORTANCE Importance
	)
{
	switch (Importance) {
		case LowImportance: return "LowImportance";
		case MediumImportance: return "MediumImportance";
		case HighImportance: return "HighImportance";
		case MediumHighImportance: return "MediumHighImportance";
		default: 
			return "InvalidImportance";
	}
}


VOID
PrintDpcInformation(
	PDPC_INFORMATION DpcInformation
	)
{
	for (ULONG i = 0; i < DpcInformation->QueueCount; i++) {
		PDPC_QUEUE DpcQueue = DpcInformation->DpcQueues[i];
		DbgPrint("DpcQueue Number %d:\nDpcDataPtr: 0x%p\nDpcQueueDepth: %d\nDpcCount: %d\nDpcObjects:\n",
			DpcQueue->ProcessorNumber,
			DpcQueue->DpcDataPtr,
			DpcQueue->DpcQueueDepth,
			DpcQueue->DpcCount
		);

		for (ULONG j = 0; j < DpcQueue->DpcQueueDepth; j++) {
			PDPC_OBJECT DpcObject = &DpcQueue->DpcObjects[j];

			DbgPrint("---------------------------------------\n\t");
			DbgPrint("DpcPtr: 0x%p\n\t", DpcObject->OriginalDpcPtr);
			DbgPrint("Type: %s\n\t", DpcTypeToString(DpcObject->DpcCopy.Type));
			DbgPrint("Importance:%s\n\t", DpcImportanceToString(DpcObject->DpcCopy.Importance));
			DbgPrint("Number: %d\n\t", DpcObject->DpcCopy.Number);
			DbgPrint("NextDpcItem: 0x%p\n\t", CONTAINING_RECORD(DpcObject->DpcCopy.DpcListEntry.Next, KDPC, DpcListEntry));
			DbgPrint("DeferredRoutine: 0x%p\n\t", DpcObject->DpcCopy.DeferredRoutine);
			DbgPrint("DeferredContext: 0x%p\n\t", DpcObject->DpcCopy.DeferredContext);
			DbgPrint("SystemArgument1: 0x%p\n\t", DpcObject->DpcCopy.SystemArgument1);
			DbgPrint("SystemArgument2: 0x%p\n\t\n", DpcObject->DpcCopy.SystemArgument2);
		}
	}
}