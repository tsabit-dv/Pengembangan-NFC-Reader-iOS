import Foundation
import CoreNFC
import UIKit

class NFCManager: NSObject,
                  ObservableObject,
                  NFCNDEFReaderSessionDelegate,
                  NFCTagReaderSessionDelegate {

    //==================================================
    // MARK: - Published Data
    //==================================================

    @Published var tagInfo:[String:String] = [:]

    private var ndefSession:NFCNDEFReaderSession?
    private var tagSession:NFCTagReaderSession?

    private var writePayload:NFCNDEFPayload?
    private var isWriting = false
    private var isDeleting = false

    //==================================================
    // MARK: - PUBLIC FUNCTIONS
    //==================================================

    //----------------------------------
    // SCAN NFC
    //----------------------------------
    func startScan() {

        tagInfo.removeAll()

        tagSession = NFCTagReaderSession(
            pollingOption: [.iso14443,.iso15693,.iso18092],
            delegate: self,
            queue: nil
        )

        tagSession?.alertMessage = "Scan NFC Tag"
        tagSession?.begin()
    }

    //----------------------------------
    // WRITE TEXT
    //----------------------------------
    func writeText(_ text:String) {

        let payload = NFCNDEFPayload.wellKnownTypeTextPayload(
            string: text,
            locale: Locale.current
        )!

        writePayload = payload
        isWriting = true
        startNDEFSession()
    }

    //----------------------------------
    // WRITE URL
    //----------------------------------
    func writeURL(_ url:String) {

        guard let u = URL(string:url) else { return }

        writePayload =
        NFCNDEFPayload.wellKnownTypeURIPayload(
            url: u
        )

        isWriting = true
        startNDEFSession()
    }

    //----------------------------------
    // DELETE RECORD
    //----------------------------------
    func deleteRecord() {

        isDeleting = true
        startNDEFSession()
    }

    private func startNDEFSession() {

        ndefSession =
        NFCNDEFReaderSession(
            delegate: self,
            queue: nil,
            invalidateAfterFirstRead: false
        )

        ndefSession?.alertMessage = "Tap NFC Tag"
        ndefSession?.begin()
    }

    //==================================================
    // MARK: - TAG READER
    //==================================================

    func tagReaderSessionDidBecomeActive(
        _ session: NFCTagReaderSession) {}

    func tagReaderSession(
        _ session: NFCTagReaderSession,
        didInvalidateWithError error: Error) {}

    //--------------------------------------------------
    // TAG DETECTED
    //--------------------------------------------------
    func tagReaderSession(
        _ session: NFCTagReaderSession,
        didDetect tags: [NFCTag]) {

        guard let tag = tags.first else { return }

        session.connect(to: tag) { error in

            if error != nil {
                session.invalidate()
                return
            }

            DispatchQueue.main.async {
                self.readTagInformation(tag)
            }

            session.invalidate()
        }
    }

    //==================================================
    // MARK: - READ TAG INFO
    //==================================================

    private func readTagInformation(_ tag: NFCTag) {

        switch tag {

        //--------------------------------------------------
        // MiFare
        //--------------------------------------------------
        case .miFare(let mifare):

            let uid =
            mifare.identifier.map {
                String(format:"%02X",$0)
            }.joined()

            tagInfo["Tag Type"] =
                "MiFare (\(detectMiFare(mifare)))"

            tagInfo["Technologies"] =
                technologies(tag)

            tagInfo["Serial Number"] = uid

            tagInfo["ATQA"] =
                mifare.historicalBytes?
                .map{String(format:"%02X",$0)}
                .joined() ?? "-"

            tagInfo["SAK"] =
                "\(mifare.mifareFamily.rawValue)"

            tagInfo["Memory Information"] =
                memoryGuess(mifare)

            readNDEF(tag)

        //--------------------------------------------------
        default:
            tagInfo["Tag Type"] = "Unsupported"
        }
    }

    //==================================================
    // MARK: - READ NDEF CONTENT
    //==================================================

    private func readNDEF(_ tag:NFCTag) {

        guard case let .miFare(mifare) = tag else { return }

        mifare.queryNDEFStatus { status, capacity, error in

            DispatchQueue.main.async {

                self.tagInfo["Size"] =
                "0 / \(capacity) Bytes"

                if status == .notSupported {
                    self.tagInfo["Data Format"] =
                    "Non-NDEF"
                    return
                }

                mifare.readNDEF { message, error in

                    guard let msg = message else {
                        self.tagInfo["Data Format"] =
                        "Empty"
                        return
                    }

                    self.tagInfo["Data Format"] =
                        "NDEF"

                    var used = 0

                    for record in msg.records {

                        used += record.payload.count

                        //----------------------------------
                        // TEXT
                        //----------------------------------
                        if let text =
                            record.wellKnownTypeTextPayload() {

                            self.tagInfo["Record"] =
                            text.0
                        }

                        //----------------------------------
                        // URL
                        //----------------------------------
                        if let url =
                            record.wellKnownTypeURIPayload() {

                            self.tagInfo["Record"] =
                            url.absoluteString

                            DispatchQueue.main.asyncAfter(
                                deadline:.now()+0.5
                            ){
                                UIApplication.shared.open(url)
                            }
                        }
                    }

                    self.tagInfo["Size"] =
                    "\(used) / \(capacity) Bytes"
                }
            }
        }
    }

    //==================================================
    // MARK: - WRITE / DELETE SESSION
    //==================================================

    func readerSession(
        _ session: NFCNDEFReaderSession,
        didInvalidateWithError error: Error) {}

    func readerSession(
        _ session: NFCNDEFReaderSession,
        didDetectNDEFs messages: [NFCNDEFMessage]) {}

    func readerSession(
        _ session: NFCNDEFReaderSession,
        didDetect tags: [NFCTag]) {

        guard let tag = tags.first else { return }

        session.connect(to: tag) { _ in

            tag.queryNDEFStatus { status,_,_ in

                guard status == .readWrite else {
                    session.invalidate()
                    return
                }

                //----------------------------------
                // DELETE
                //----------------------------------
                if self.isDeleting {

                    let empty =
                    NFCNDEFMessage(records: [])

                    tag.writeNDEF(empty){_ in
                        session.alertMessage="Deleted"
                        session.invalidate()
                    }

                    self.isDeleting=false
                    return
                }

                //----------------------------------
                // WRITE
                //----------------------------------
                guard let payload =
                        self.writePayload else {
                    session.invalidate()
                    return
                }

                let msg =
                NFCNDEFMessage(records:[payload])

                tag.writeNDEF(msg){_ in
                    session.alertMessage="Write Success"
                    session.invalidate()
                }

                self.isWriting=false
            }
        }
    }

    //==================================================
    // MARK: - HELPERS
    //==================================================

    private func detectMiFare(
        _ tag:NFCMiFareTag)->String {

        switch tag.mifareFamily {

        case .desfire: return "DESFire EV1/EV2/EV3"
        case .ultralight: return "Ultralight"
        case .plus: return "MiFare Plus"
        default: return "Unknown"
        }
    }

    private func technologies(
        _ tag:NFCTag)->String {

        switch tag {
        case .miFare: return "ISO14443-A"
        case .iso15693: return "ISO15693"
        case .feliCa: return "FeliCa"
        default: return "-"
        }
    }

    private func memoryGuess(
        _ tag:NFCMiFareTag)->String {

        switch tag.mifareFamily {
        case .ultralight:
            return "48-144 Bytes"
        case .desfire:
            return "2K / 4K / 8K"
        default:
            return "Unknown"
        }
    }
}
