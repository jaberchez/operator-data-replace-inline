/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	datav1alpha1 "github.com/jaberchez/operator-data-replace-inline/api/v1alpha1"
	"github.com/jaberchez/operator-data-replace-inline/pkg/utils"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// DataReplaceInlineReconciler reconciles a DataReplaceInline object
type DataReplaceInlineReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=data.example.com,resources=datareplaceinlines,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=data.example.com,resources=datareplaceinlines/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=data.example.com,resources=datareplaceinlines/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the DataReplaceInline object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.9.2/pkg/reconcile
func (r *DataReplaceInlineReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logr := log.FromContext(ctx)

	instance := &datav1alpha1.DataReplaceInline{}

	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		if apierrors.IsNotFound(err) {
			// We'll ignore not-found errors, since we can get them on deleted requests.
			return ctrl.Result{}, nil
		}

		logr.Error(err, "unable to fetch DataReplaceInline instance")
		return ctrl.Result{}, err
	}

	if len(instance.Spec.Manifest) == 0 {
		logr.Error(fmt.Errorf("manifest is empty"), fmt.Sprintf("manifest field is empty in %v", instance))
		return ctrl.Result{}, fmt.Errorf("manifest field is empty in %v", instance)
	}

	k8s, err := utils.NewK8sUtil(r.Client, instance.Spec.Manifest, req)

	if err != nil {
		return ctrl.Result{}, err
	}

	err = k8s.ProcessManifest()

	if err != nil {
		return ctrl.Result{}, err
	}

	// Decode manifest
	err = k8s.DecodeManifest()

	if err != nil {
		return ctrl.Result{}, err
	}

	if instance.Spec.SetOwnerReferences {
		// Add OwnerReference
		k8s.AddOwnerReference(instance.TypeMeta, instance.ObjectMeta)
	}

	// Check if the object already exists
	objExists, err := k8s.ResourceExists()

	if err != nil {
		return ctrl.Result{}, err
	}

	if objExists {
		// The object exists, update
		err = k8s.UpdateResource()

		if err != nil {
			return ctrl.Result{}, err
		}
	} else {
		// The object does not exist, create
		err = k8s.CreateResource()

		if err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *DataReplaceInlineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&datav1alpha1.DataReplaceInline{}).
		Complete(r)
}
