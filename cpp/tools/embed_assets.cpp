#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

void FileToCArray(const std::string& path, const std::string& varName, std::ostream& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "Warning: Could not open " << path << std::endl;
        out << "const unsigned char " << varName << "[] = { 0x00 };\n";
        out << "const size_t " << varName << "_LEN = 0;\n\n";
        return;
    }

    std::vector<unsigned char> data((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());

    out << "const unsigned char " << varName << "[] = {\n    ";
    for (size_t i = 0; i < data.size(); ++i) {
        out << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << ",";
        if ((i + 1) % 16 == 0 && i + 1 < data.size()) {
            out << "\n    ";
        }
    }
    out << "\n    0x00\n};\n";
    out << std::dec;
    out << "const size_t " << varName << "_LEN = " << data.size() << ";\n\n";
}

int main(int argc, char* argv[]) {
    std::ofstream out("cpp/include/embedded_assets.h", std::ios::binary);
    if (!out) {
        std::cerr << "Error writing cpp/include/embedded_assets.h" << std::endl;
        return 1;
    }

    out << "#pragma once\n";
    out << "#include <cstddef>\n\n";

    std::ifstream reactDist("frontend/dist/index.html", std::ios::binary);
    if (reactDist.is_open()) {
        reactDist.close();
        FileToCArray("frontend/dist/index.html", "INDEX_HTML", out);
        out << "const unsigned char STYLE_CSS[] = { 0x00 };\n";
        out << "const size_t STYLE_CSS_LEN = 0;\n\n";
        out << "const unsigned char APP_JS[] = { 0x00 };\n";
        out << "const size_t APP_JS_LEN = 0;\n\n";
        std::cout << "Successfully embedded React 18 production bundle into C++ header!" << std::endl;
    } else {
        FileToCArray("ui/web/index.html", "INDEX_HTML", out);
        FileToCArray("ui/web/style.css", "STYLE_CSS", out);
        FileToCArray("ui/web/app.js", "APP_JS", out);
        std::cout << "Successfully embedded web assets into C++ header!" << std::endl;
    }

    return 0;
}
