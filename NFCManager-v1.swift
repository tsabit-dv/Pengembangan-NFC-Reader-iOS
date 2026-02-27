```swift
import Foundation
import CoreNFC
import Combine

class NFCManager: NSObject,
                  ObservableObject,
                  NFCTagReaderSessionDelegate,
                  NFCNDEFReaderSessionDelegate {

    //--------------------------------------------------
    // SESSION
    //--------------------------------------------------
    var session: NFCTagReaderSession?
    var writeSession: NFCNDEFReaderSession?

    //--------------------------------------------------
    // OUTPUT
    //--------------------------------------------------
    @Published var tagInfo: [String:String] = [:]

    //--------------------------------------------------
    // START SCAN
    //--------------------------------------------------
    func startScan() {

        guard NFCTagReaderSession.readingAvailable else {
            print("NFC Not Available")
            return
        }

        session = NFCTagReaderSession(
            pollingOption: [.iso14443],
            delegate: self,
            queue: nil
        )

        session?.alertMessage = "Scan NFC Card"
        session?.begin()
    }

    //--------------------------------------------------
    // WRITE TEXT
    //--------------------------------------------------
    func writeText(_ text:String) {

        writeSession = NFCNDEFReaderSession(
            delegate: self,
            queue: nil,
            invalidateAfterFirstRead:false
        )

        writeSession?.alertMessage =
        "Tap NFC tag to WRITE"
        writeSession?.begin()

        textPayload = text
    }

    private var textPayload:String = ""

    //--------------------------------------------------
    // TAG DETECTED
    //--------------------------------------------------
    func tagReaderSession(
        _ session: NFCTagReaderSession,
        didDetect tags:[NFCTag]
    ) {

        guard let tag = tags.first else { return }

        session.connect(to: tag) { error in
            if error != nil {
                session.invalidate()
                return
            }

            self.parseTag(tag)
        }
    }

    func tagReaderSessionDidBecomeActive(
        _ session: NFCTagReaderSession) {}

    func tagReaderSession(
        _ session: NFCTagReaderSession,
        didInvalidateWithError error:Error){}

    //--------------------------------------------------
    // MAIN PARSER
    //--------------------------------------------------
    private func parseTag(_ tag:NFCTag) {

        DispatchQueue.main.async {
            self.tagInfo.removeAll()
        }

        switch tag {

        //--------------------------------------------------
        // ISO7816 (DESFire / Type4)
        //--------------------------------------------------
        case .iso7816(let iso):

            let uid = hex(iso.identifier)
            let ats = iso.historicalBytes ?? Data()

            let chip = detectDESFire(ats)
            let memory = detectMemoryFromATS(ats)

            DispatchQueue.main.async {

                self.tagInfo["Tag Type"] =
                "ISO14443-4\n\(chip)"

                self.tagInfo["Technologies"] =
                "Type A, ISO-DEP"

                self.tagInfo["Serial Number"] = uid

                self.tagInfo["ATQA"] =
                "Restricted by iOS"

                self.tagInfo["SAK"] =
                "Restricted by iOS"

                self.tagInfo["Memory Information"] =
                memory

                self.tagInfo["Data Format"] =
                "NFC Forum Type 4"

                self.readNDEF(from: tag)
            }

        //--------------------------------------------------
        // MIFARE
        //--------------------------------------------------
        case .miFare(let mifare):

            let uid = hex(mifare.identifier)

            DispatchQueue.main.async {

                self.tagInfo["Tag Type"] =
                "ISO14443-3A\nNXP \(self.familyName(mifare.mifareFamily))"

                self.tagInfo["Technologies"] =
                self.techFromFamily(mifare.mifareFamily)

                self.tagInfo["Serial Number"] = uid

                self.tagInfo["ATQA"] =
                "Restricted by iOS"

                self.tagInfo["SAK"] =
                "Restricted by iOS"

                self.tagInfo["Memory Information"] =
                self.memoryFromFamily(mifare.mifareFamily)

                self.tagInfo["Data Format"] =
                "NFC Forum"

                self.readNDEF(from: tag)
            }

        default:
            break
        }

        session?.invalidate()
    }

    //--------------------------------------------------
    // READ REAL NDEF SIZE + RECORD
    //--------------------------------------------------
    private func readNDEF(from tag:NFCTag) {

        guard case let .iso7816(iso) = tag else { return }

        iso.queryNDEFStatus { status,
                              capacity,
                              error in

            DispatchQueue.main.async {

                if status == .readWrite ||
                   status == .readOnly {

                    self.tagInfo["Size"] =
                    "\(capacity) Bytes"

                    iso.readNDEF { message, error in

                        guard let message else { return }

                        var index = 1

                        for record in message.records {

                            let text =
                            String(
                              data:record.payload.dropFirst(3),
                              encoding:.utf8
                            ) ?? "Binary"

                            self.tagInfo[
                              "Record \(index)"
                            ] = text

                            index += 1
                        }
                    }
                }
            }
        }
    }

    //--------------------------------------------------
    // WRITE IMPLEMENTATION
    //--------------------------------------------------
    func readerSession(
        _ session:NFCNDEFReaderSession,
        didDetect tags:[NFCNDEFTag]) {

        guard let tag = tags.first else { return }

        session.connect(to: tag) { error in

            let payload =
            NFCNDEFPayload.wellKnownTypeTextPayload(
                string:self.textPayload,
                locale:Locale.current
            )!

            let message =
            NFCNDEFMessage(records:[payload])

            tag.writeNDEF(message) { error in
                session.alertMessage="Write Success"
                session.invalidate()
            }
        }
    }

    func readerSession(
        _ session:NFCNDEFReaderSession,
        didDetectNDEFs messages:[NFCNDEFMessage]) {}

    func readerSession(
        _ session:NFCNDEFReaderSession,
        didInvalidateWithError error:Error){}

    //--------------------------------------------------
    // HELPERS
    //--------------------------------------------------
    private func hex(_ data:Data)->String{
        data.map{
            String(format:"%02X",$0)
        }.joined(separator:":")
    }

    private func detectDESFire(_ ats:Data)->String{

        if ats.contains(0x77){
            return "MIFARE DESFire EV3"
        }

        if ats.contains(0x75){
            return "MIFARE DESFire EV2"
        }

        return "MIFARE DESFire EV1"
    }

    private func detectMemoryFromATS(
        _ ats:Data)->String{

        if ats.contains(0x77){
            return "8KB EEPROM"
        }

        if ats.contains(0x75){
            return "4KB EEPROM"
        }

        return "2KB EEPROM"
    }

    private func familyName(
        _ f:NFCMiFareFamily)->String{

        switch f{
        case .ultralight: return "Ultralight"
        case .plus: return "Plus"
        case .desfire: return "DESFire"
        default: return "Unknown"
        }
    }

    private func techFromFamily(
        _ f:NFCMiFareFamily)->String{

        switch f{
        case .desfire:
            return "Type A, ISO-DEP"
        default:
            return "Type A"
        }
    }

    private func memoryFromFamily(
        _ f:NFCMiFareFamily)->String{

        switch f{
        case .ultralight:
            return "512 Bytes"
        case .plus:
            return "2K / 4K"
        case .desfire:
            return "2K / 4K / 8K"
        default:
            return "Unknown"
        }
    }
}
```
