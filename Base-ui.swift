//--------------------------------
// TAG INFO LIST
//--------------------------------
List {

    let orderedKeys = [
        "Tag Type",
        "Technologies",
        "Serial Number",
        "ATQA",
        "SAK",
        "Memory Information",
        "Data Format",
        "Size"
    ]

    //--------------------------------
    // MAIN INFO
    //--------------------------------
    ForEach(orderedKeys, id:\.self) { key in

        if let value = nfc.tagInfo[key] {

            VStack(alignment:.leading, spacing:4) {

                Text(key)
                    .font(.headline)

                Text(value)
                    .font(.system(
                        size:14,
                        design:.monospaced
                    ))
                    .foregroundColor(.gray)
            }
            .padding(.vertical,4)
        }
    }

    //--------------------------------
    // RECORD SECTION
    //--------------------------------
    ForEach(
        nfc.tagInfo.keys
            .filter { $0.contains("Record") }
            .sorted(),
        id:\.self
    ) { key in

        VStack(alignment:.leading) {

            Text(key)
                .font(.headline)

            Text(nfc.tagInfo[key] ?? "")
                .font(.system(
                    size:14,
                    design:.monospaced
                ))
        }
    }
}

