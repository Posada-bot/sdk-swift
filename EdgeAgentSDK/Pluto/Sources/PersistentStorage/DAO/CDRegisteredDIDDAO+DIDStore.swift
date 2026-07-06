import Combine
import CoreData
import Domain

extension CDRegisteredDIDDAO: DIDStore {
    func addDID(did: DID, keyPairIndex: Int, alias: String?) -> AnyPublisher<Void, Error> {
        updateOrCreate(did.string, context: writeContext) { cdobj, _ in
            cdobj.parseFrom(did: did, keyPairIndex: keyPairIndex, alias: alias)
        }
        .handleEvents(receiveOutput: { [readContext, writeContext] _ in
            // POS-243 SDKPROBE (read-only, measurement only — no behavior change):
            // immediately after the write completes, count CDRegisteredDID DIRECTLY on
            // BOTH the write context (editContext) and the read context
            // (mainContext/viewContext). Splits the same-coordinator defect:
            //   editContext>0 & viewContext=0 => sibling-invisible (read never merges) -> merge fix
            //   editContext=0                 => save not landing in-session          -> write-path fix
            let entityName = CDRegisteredDID.entity().name ?? "CDRegisteredDID"
            func count(_ ctx: NSManagedObjectContext) -> Int {
                var n = -1
                ctx.performAndWait {
                    let req = NSFetchRequest<NSFetchRequestResult>(entityName: entityName)
                    n = (try? ctx.count(for: req)) ?? -1
                }
                return n
            }
            NSLog("POS-243 SDKPROBE editContext=%d viewContext=%d", count(writeContext), count(readContext))
        })
        .map { _ in () }
        .eraseToAnyPublisher()
    }

    func removeDID(did: DID) -> AnyPublisher<Void, Error> {
        deleteByIDsPublisher([did.string], context: writeContext)
    }

    func removeAll() -> AnyPublisher<Void, Error> {
        deleteAllPublisher(context: writeContext)
    }
}

private extension CDRegisteredDID {
    func parseFrom(did: DID, keyPairIndex: Int, alias: String?) {
        self.did = did.string
        schema = did.schema
        method = did.method
        methodId = did.methodId
        keyIndex = Int64(keyPairIndex)
        self.alias = alias
    }
}
