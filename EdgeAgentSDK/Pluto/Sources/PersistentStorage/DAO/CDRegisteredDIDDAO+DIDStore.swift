import Combine
import CoreData
import Domain

extension CDRegisteredDIDDAO: DIDStore {
    func addDID(did: DID, keyPairIndex: Int, alias: String?) -> AnyPublisher<Void, Error> {
        updateOrCreate(did.string, context: writeContext) { cdobj, _ in
            cdobj.parseFrom(did: did, keyPairIndex: keyPairIndex, alias: alias)
        }
        .handleEvents(receiveOutput: { [readContext, writeContext] _ in
            // POS-243 CONFIRMING probe (read-only): with the fix, storePrismDID calls this
            // DAO, so it now RUNS. Count CDRegisteredDID on both contexts right AFTER the
            // register write — the "after" reading (expect editContext=1, viewContext=1).
            // The storeDID SDKPROBE fires BEFORE this and is the 0/0 baseline.
            let entityName = CDRegisteredDID.entity().name ?? "CDRegisteredDID"
            func count(_ ctx: NSManagedObjectContext) -> Int {
                var n = -1
                ctx.performAndWait {
                    n = (try? ctx.count(for: NSFetchRequest<NSFetchRequestResult>(entityName: entityName))) ?? -1
                }
                return n
            }
            NSLog("POS-243 SDKPROBE-REGISTER CDRegisteredDID editContext=%d viewContext=%d",
                  count(writeContext), count(readContext))
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
