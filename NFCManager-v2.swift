```swift
import Foundation
import CoreNFC
import Combine
import UIKit

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
    @Published var tagInfo:[String:String] = [:]

    private var payloadToWrite:String = ""
    private var writeModeURL = false

    //--------------------------------------------------
    // START SCAN
    //--------------------------------------------------
    func startScan() {

        guard NFCTagReaderSession.readingAvailable else {
            print("NFC Not Supported")
            return
        }

        session = NFCTagReaderSession(
            pollingOption: [.iso14443],
            delegate: self
        )

        session?.alertMessage = "Scan NFC Tag"
        session?.begin()
    }

    //--------------------------------------------------
    // WRITE TEXT
    //--------------------------------------------------
    func writeText(_ text:String) {
        payloadToWrite = text
        writeModeURL = false
        startWrite()
    }

    //--------------------------------------------------
    // WRITE URL
    //--------------------------------------------------
    func writeURL(_ url:String) {
        payloadToWrite = url
        writeModeURL = true
        startWrite()
    }

    private func startWrite() {

        writeSession = NFCNDEFReaderSession(
            delegate: self,
            queue: nil,
            invalidateAfterFirstRead:false
        )

        writeSession?.alertMessage =
        "Tap NFC Tag to write"
        writeSession?.begin()
    }

    //--------------------------------------------------
    // TAG DETECTED
    //--------------------------------------------------
    func tagReaderSession(
        _ session: NFCTagReaderSession,
        didDetect tags:[NFCTag]) {

        guard let tag = tags.first else { return }

        session.connect(to: tag) { _ in
            self.parseTag(tag)
        }
    }

    func tagReaderSessionDidBecomeActive(
        _ session: NFCTagReaderSession) {}

    func tagReaderSession(
        _ session: NFCTagReaderSession,
        didInvalidateWithError error:Error){}

    //--------------------------------------------------
    // PARSE TAG
    //--------------------------------------------------
    private func parseTag(_ tag:NFCTag) {

        DispatchQueue.main.async {
            self.tagInfo.removeAll()
        }

        switch tag {

        //--------------------------------
        // ISO7816 / DESFire
        //--------------------------------
        case .iso7816(let iso):

            let uid = hex(iso.identifier)
            let ats = iso.historicalBytes ?? Data()

            DispatchQueue.main.async {

                self.tagInfo["Tag Type"] =
                "ISO14443-4\n\(self.detectDESFire(ats))"

                self.tagInfo["Technologies"] =
                "Type A, ISO-DEP"

                self.tagInfo["Serial Number"] = uid
                self.tagInfo["ATQA"] =
                "Restricted by iOS"
                self.tagInfo["SAK"] =
                "Restricted by iOS"

                self.tagInfo["Memory Information"] =
                self.detectMemoryFromATS(ats)

                self.tagInfo["Data Format"] =
                "NFC Forum Type 4"
            }

            readNDEF(from: tag)

        //--------------------------------
        // MIFARE
        //--------------------------------
        case .miFare(let mifare):

            DispatchQueue.main.async {

                self.tagInfo["Tag Type"] =
                "ISO14443-3A\nNXP \(self.family(mifare.mifareFamily))"

                self.tagInfo["Technologies"] =
                self.tech(mifare.mifareFamily)

                self.tagInfo["Serial Number"] =
                self.hex(mifare.identifier)

                self.tagInfo["ATQA"] =
                "Restricted by iOS"

                self.tagInfo["SAK"] =
                "Restricted by iOS"

                self.tagInfo["Memory Information"] =
                self.memory(mifare.mifareFamily)

                self.tagInfo["Data Format"] =
                "NFC Forum"
            }

            readNDEF(from: tag)

        default:
            break
        }

        session?.invalidate()
    }

    //--------------------------------------------------
    // READ NDEF + AUTO URL OPEN
    //--------------------------------------------------
    private func readNDEF(from tag:NFCTag) {

        guard case let .iso7816(iso) = tag else { return }

        iso.queryNDEFStatus { status,
                              capacity,
                              _ in

            DispatchQueue.main.async {

                if status == .readOnly ||
                   status == .readWrite {

                    self.tagInfo["Size"] =
                    "\(capacity) Bytes"

                    iso.readNDEF { message,_ in

                        guard let message else { return }

                        var index = 1

                        for record in message.records {

                            if let text =
                                record.wellKnownTypeTextPayload()?.0 {

                                self.tagInfo[
                                "Record \(index)"
                                ] = text
                            }

                            if let url =
                                record.wellKnownTypeURIPayload() {

                                let urlString =
                                url.absoluteString

                                self.tagInfo[
                                "Record \(index)"
                                ] = urlString

                                self.tagInfo[
                                "Detected URL"
                                ] = urlString

                                self.openBrowser(url)
                            }

                            index += 1
                        }
                    }
                }
            }
        }
    }

    //--------------------------------------------------
    // WRITE HANDLER
    //--------------------------------------------------
    func readerSession(
        _ session:NFCNDEFReaderSession,
        didDetect tags:[NFCNDEFTag]) {

        guard let tag = tags.first else { return }

        session.connect(to: tag) { _ in

            var payload:NFCNDEFPayload

            if self.writeModeURL {

                payload =
                NFCNDEFPayload.wellKnownTypeURIPayload(
                    URL(string:self.payloadToWrite)!
                )!

            } else {

                payload =
                NFCNDEFPayload.wellKnownTypeTextPayload(
                    string:self.payloadToWrite,
                    locale:.current)!
            }

            let message =
            NFCNDEFMessage(records:[payload])

            tag.writeNDEF(message) { _ in
                session.alertMessage="Write Success"
                session.invalidate()
            }
        }
    }

    func readerSession(
        _ session:NFCNDEFReaderSession,
        didDetectNDEFs messages:[NFCNDEFMessage]){}

    func readerSession(
        _ session:NFCNDEFReaderSession,
        didInvalidateWithError error:Error){}

    //--------------------------------------------------
    // OPEN SAFARI
    //--------------------------------------------------
    private func openBrowser(_ url:URL){

        DispatchQueue.main.asyncAfter(
            deadline:.now()+0.5){

            UIApplication.shared.open(url)
        }
    }

    //--------------------------------------------------
    // HELPERS
    //--------------------------------------------------
    private func hex(_ data:Data)->String{
        data.map{
            String(format:"%02X",$0)
        }.joined(separator:":")
    }

    private func detectDESFire(_ ats:Data)->String{
        if ats.contains(0x77){return "MIFARE DESFire EV3"}
        if ats.contains(0x75){return "MIFARE DESFire EV2"}
        return "MIFARE DESFire EV1"
    }

    private func detectMemoryFromATS(
        _ ats:Data)->String{
        if ats.contains(0x77){return "8KB EEPROM"}
        if ats.contains(0x75){return "4KB EEPROM"}
        return "2KB EEPROM"
    }

    private func family(
        _ f:NFCMiFareFamily)->String{
        switch f{
        case .ultralight:return "Ultralight"
        case .plus:return "Plus"
        case .desfire:return "DESFire"
        default:return "Unknown"
        }
    }

    private func tech(
        _ f:NFCMiFareFamily)->String{
        f == .desfire ?
        "Type A, ISO-DEP":"Type A"
    }

    private func memory(
        _ f:NFCMiFareFamily)->String{
        switch f{
        case .ultralight:return "512 Bytes"
        case .plus:return "2K / 4K"
        case .desfire:return "2K / 4K / 8K"
        default:return "Unknown"
        }
    }
}
```
