package template

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hashicorp/hil"
	"github.com/hashicorp/hil/ast"
	"github.com/hashicorp/terraform/config"
	"github.com/hashicorp/terraform/helper/pathorcontents"
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceFile() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceFileRead,

		Schema: map[string]*schema.Schema{
			"template": &schema.Schema{
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "Contents of the template",
				ConflictsWith: []string{"filename"}, },
			"filename": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "file to read template from",
				// Make a "best effort" attempt to relativize the file path.
				StateFunc: func(v interface{}) string {
					if v == nil || v.(string) == "" {
						return ""
					}
					pwd, err := os.Getwd()
					if err != nil {
						return v.(string)
					}
					rel, err := filepath.Rel(pwd, v.(string))
					if err != nil {
						return v.(string)
					}
					return rel
				},
				Deprecated:    "Use the 'template' attribute instead.",
				ConflictsWith: []string{"template"},
			},
			"vars": &schema.Schema{
				Type:         schema.TypeMap,
				Optional:     true,
				Default:      make(map[string]interface{}),
				Description:  "variables to substitute",
				ValidateFunc: validateVarsAttribute,
			},
			"post_render": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "post processing script to run after template is rendered.",
			},
			"rendered": &schema.Schema{
				Type:        schema.TypeString,
				Computed:    true,
				Description: "rendered template",
			},
		},
	}
}

func dataSourceFileRead(d *schema.ResourceData, meta interface{}) error {
	rendered, err := renderFile(d)
	if err != nil {
		return err
	}
	d.Set("rendered", rendered)
	d.SetId(hash(rendered))
	return nil
}

type templateRenderError error

func renderFile(d *schema.ResourceData) (string, error) {
	template := d.Get("template").(string)
	filename := d.Get("filename").(string)
	vars := d.Get("vars").(map[string]interface{})
	postRender := d.Get("post_render").(string)

	contents := template
	if template == "" && filename != "" {
		data, _, err := pathorcontents.Read(filename)
		if err != nil {
			return "", err
		}

		contents = data
	}

	rendered, err := execute(contents, vars)
	if err != nil {
		return "", templateRenderError(
			fmt.Errorf("failed to render %v: %v", filename, err),
		)
	}

	if postRender != "" {
		rendered, err = executeScript(postRender, rendered)
		if err != nil {
			return "", templateRenderError(
				fmt.Errorf("post_render script failed to render %v: %v", filename, err),
			)
		}
	}

	return rendered, nil
}

func executeScript(command, rendered string) (string, error) {
	// Execute the command using a shell
	var shell, flag string
	if runtime.GOOS == "windows" {
		shell = "cmd"
		flag = "/C"
	} else {
		shell = "/bin/sh"
		flag = "-c"
	}

	// Setup the command
	cmd := exec.Command(shell, flag, command)
	output := new(bytes.Buffer)
	cmd.Stdin = bytes.NewBufferString(rendered)
	cmd.Stderr = output
	cmd.Stdout = output
	// Run the command to completion
	err := cmd.Run()

	if err != nil {
		return "", fmt.Errorf("Error running command '%s': %v. Output: %s",
			command, err, output.Bytes())
	}

	return output.String(), nil
}

// execute parses and executes a template using vars.
func execute(s string, vars map[string]interface{}) (string, error) {
	root, err := hil.Parse(s)
	if err != nil {
		return "", err
	}

	varmap := make(map[string]ast.Variable)
	for k, v := range vars {
		// As far as I can tell, v is always a string.
		// If it's not, tell the user gracefully.
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("unexpected type for variable %q: %T", k, v)
		}
		varmap[k] = ast.Variable{
			Value: s,
			Type:  ast.TypeString,
		}
	}

	cfg := hil.EvalConfig{
		GlobalScope: &ast.BasicScope{
			VarMap:  varmap,
			FuncMap: config.Funcs(),
		},
	}

	result, err := hil.Eval(root, &cfg)
	if err != nil {
		return "", err
	}
	if result.Type != hil.TypeString {
		return "", fmt.Errorf("unexpected output hil.Type: %v", result.Type)
	}

	return result.Value.(string), nil
}

func hash(s string) string {
	sha := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sha[:])
}

func validateVarsAttribute(v interface{}, key string) (ws []string, es []error) {
	// vars can only be primitives right now
	var badVars []string
	for k, v := range v.(map[string]interface{}) {
		switch v.(type) {
		case []interface{}:
			badVars = append(badVars, fmt.Sprintf("%s (list)", k))
		case map[string]interface{}:
			badVars = append(badVars, fmt.Sprintf("%s (map)", k))
		}
	}
	if len(badVars) > 0 {
		es = append(es, fmt.Errorf(
			"%s: cannot contain non-primitives; bad keys: %s",
			key, strings.Join(badVars, ", ")))
	}
	return
}
