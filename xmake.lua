set_project("encrypto")
set_languages("c99")

add_rules("mode.debug", "mode.release")

add_requires("mbedtls", {configs = {shared = false}})
add_rules("plugin.compile_commands.autoupdate")

rule("generate_keys")
    on_load(function (target)
        local config = import("core.project.config")

        local builddir = config.builddir() or "build"
        local projectdir = os.projectdir()
        local gen_dir = path.join(projectdir, builddir, "generated")
        target:data_set("generated_dir", gen_dir)
        target:add("includedirs", gen_dir, {public = true})
        local script_path = path.join(projectdir, "scripts", "generate_keys.py")
        target:data_set("keygen_script", script_path)
    end)

    before_build(function (target)
        local find_program = import("lib.detect.find_program")

        local gen_dir = target:data("generated_dir")
        assert(gen_dir, "generated directory not set")
        os.mkdir(gen_dir)

        local private_pem = path.join(gen_dir, "rsa_private.pem")
        local public_pem = path.join(gen_dir, "rsa_public.pem")
        local private_header = path.join(gen_dir, "rsa_private_key.h")
        local public_header = path.join(gen_dir, "rsa_public_key.h")

        if os.isfile(private_pem) and os.isfile(public_pem) and os.isfile(private_header) and os.isfile(public_header) then
            return
        end

        local script_path = target:data("keygen_script")
        assert(script_path and os.isfile(script_path), "key generation script missing")

        local python_prog = os.getenv("PYTHON")
        if not python_prog or #python_prog == 0 then
            python_prog = find_program("python3") or find_program("python")
        end
        assert(python_prog, "python interpreter not found; set PYTHON env var or install python3")

        os.vrunv(python_prog, {script_path, private_pem, public_pem, private_header, public_header})
    end)

rule_end()

target("keys")
    set_kind("phony")
    add_rules("generate_keys")


target("hybrid_encrypt")
    set_kind("binary")
    add_deps("keys")
    add_files("src/hybrid_encrypt.c", "src/key_data.c")
    add_packages("mbedtls")
    add_includedirs("include", "$(builddir)/generated")


target("hybrid_decrypt")
    set_kind("binary")
    add_deps("keys")
    add_files("src/hybrid_decrypt.c", "src/key_data.c")
    add_packages("mbedtls")
    add_includedirs("include", "$(builddir)/generated")
