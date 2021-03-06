#include "file_util.hh"

extern "C" {
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
}

#include <cstring>
#include <sstream>

/**
 * Adapted from an answer by "Evan Teran" from this stack overflow question:
 * http://stackoverflow.com/questions/236129/split-a-string-in-c
 */
std::vector<std::string>
split(const std::string & s, char delim)
{
    std::vector<std::string> elems;
    std::stringstream        ss(s);
    std::string              item;
    while (getline(ss, item, delim)) {
        if (!item.empty()) {
            elems.push_back(item);
        }
    }
    return elems;
}

/**
 * Adapted from an answer by "dash-tom-bang" from this stack overflow question:
 * http://stackoverflow.com/questions/5772992/get-relative-path-from-two-absolute-paths
 */
std::string
get_relative_path(const std::string & to, const std::string & from)
{
    std::vector<std::string> to_dirs = split(to, '/');
    std::vector<std::string> from_dirs = split(from, '/');

    std::string output;
    output.reserve(to.size());

    auto       to_it = to_dirs.begin();
    const auto to_end = to_dirs.end();
    auto       from_it = from_dirs.begin();
    const auto from_end = from_dirs.end();

    while ((to_it != to_end) && (from_it != from_end) && *to_it == *from_it) {
        ++to_it;
        ++from_it;
    }

    while (from_it != from_end) {
        output += "../";
        ++from_it;
    }

    while (to_it != to_end) {
        output += *to_it;
        ++to_it;

        if (to_it != to_end) {
            output += "/";
        }
    }

    return output;
}

/**
 * Returns a std::string without '..' and '.'
 *
 * Preconditions:  path must be an absolute path
 * Postconditions: if path is empty or not an absolute path, return original
 *                 path, otherwise, return path after resolving '..' and '.'
 */
std::string
get_canonicalized_path(const std::string & path)
{
    if (path.empty() || path[0] != '/') {
        return path;
    }

    std::vector<std::string> parts = split(path, '/');
    std::vector<std::string> canonicalized_path;

    auto       parts_it = parts.begin();
    const auto parts_end = parts.end();

    while (parts_it != parts_end) {
        if (*parts_it == ".." && !canonicalized_path.empty()) {
            canonicalized_path.pop_back();
        } else if (*parts_it != "." && *parts_it != "..") {
            canonicalized_path.push_back(*parts_it);
        }

        ++parts_it;
    }

    auto       path_it = canonicalized_path.begin();
    const auto path_end = canonicalized_path.end();

    std::string output;
    output.reserve(path.size());
    output += "/";
    while (path_it != path_end) {
        output += *path_it;

        ++path_it;
        if (path_it != path_end) {
            output += "/";
        }
    }

    return output;
}

/**
 * Adapted from an answer by "Mark" from this stack overflow question:
 * http://stackoverflow.com/questions/675039/how-can-i-create-directory-tree-in-c-linux
 */
bool
mkpath(const std::string & path)
{
    bool success = false;
    int  ret = mkdir(path.c_str(), 0775);
    if (ret == -1) {
        switch (errno) {
            case ENOENT:
                if (mkpath(path.substr(0, path.rfind('/'))))
                    success = 0 == mkdir(path.c_str(), 0775);
                else
                    success = false;
                break;
            case EEXIST: success = true; break;
            default: success = false; break;
        }
    } else {
        success = true;
    }

    return success;
}

/**
 * Adapted from an answer by "asveikau" from this stack overflow question:
 * http://stackoverflow.com/questions/2256945/removing-a-non-empty-directory-programmatically-in-c-or-c
 */
bool
rmpath(const char * path)
{
    DIR *  d = opendir(path);
    size_t path_len = strlen(path);
    int    r = -1;

    if (d) {
        struct dirent * p;

        r = 0;

        while (!r && (p = readdir(d))) {
            int    r2 = -1;
            char * buf;
            size_t len;

            /* Skip the names "." and ".." as we don't want to recurse on them. */
            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) {
                continue;
            }

            len = path_len + strlen(p->d_name) + 2;
            buf = (char *)malloc(len);

            if (buf) {
                struct stat statbuf;

                snprintf(buf, len, "%s/%s", path, p->d_name);

                if (!stat(buf, &statbuf)) {
                    if (S_ISDIR(statbuf.st_mode)) {
                        r2 = rmpath(buf);
                    } else {
                        r2 = unlink(buf);
                    }
                }

                free(buf);
            }

            r = r2;
        }

        closedir(d);
    }

    if (!r) {
        r = rmdir(path);
    }

    return r;
}
