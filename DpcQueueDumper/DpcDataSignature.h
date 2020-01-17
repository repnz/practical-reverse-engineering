#pragma once
#include <ntifs.h>

typedef struct _DPC_OBJECT {
	PKDPC OriginalDpcPtr;
	KDPC DpcCopy;
} DPC_OBJECT, *PDPC_OBJECT;

typedef struct _DPC_QUEUE {
	PVOID DpcDataPtr;
	ULONG ProcessorNumber;	
	ULONG DpcQueueDepth;
	ULONG DpcCount;
	DPC_OBJECT DpcObjects[1];
} DPC_QUEUE, *PDPC_QUEUE;

typedef struct _DPC_INFORMATION {
	PDPC_QUEUE* DpcQueues;
	ULONG QueueCount;
	ULONG TotalDpcQueueDepth;
} DPC_INFORMATION, *PDPC_INFORMATION;

NTSTATUS
InitializeDpcSignature(
	VOID
	);

VOID
FreeDpcInformation(
	PDPC_INFORMATION Information
	);

//
// This method can be called at >= DISPATCH_LEVEL. 
// (At passive level it would be useless because the queue is always empty at PASSIVE_LEVEL)
//
NTSTATUS
GetDpcInformation(
	__out PDPC_INFORMATION DpcInformation
	);