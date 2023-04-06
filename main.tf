data "aws_region" "current" {}

data "aws_eks_cluster" "eks" {
  name = var.eks_cluster_name
}

module "service_monitor_crd" {
  source = "./addons/service_monitor_crd"
}

data "aws_subnet_ids" "private_subnet_ids" {
  vpc_id = var.vpc_id # Replace with your VPC ID
  tags = {
    Subnet-group = "private"
  }
}

resource "aws_iam_instance_profile" "karpenter_profile" {
  role        = var.worker_iam_role_name
  name_prefix = var.eks_cluster_name
  tags = merge(
    { "Name"        = format("%s-%s-karpenter-profile", var.environment, var.name)
      "Environment" = var.environment
    }
  )
}

data "aws_eks_addon_version" "this" {
  addon_name = "aws-ebs-csi-driver"
  # Need to allow both config routes - for managed and self-managed configs
  kubernetes_version = data.aws_eks_cluster.eks.version
  most_recent        = true
}

data "aws_iam_policy_document" "aws_ebs_csi_driver" {
  count = var.enable_amazon_eks_aws_ebs_csi_driver ? 1 : 0

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:CreateSnapshot",
      "ec2:AttachVolume",
      "ec2:DetachVolume",
      "ec2:ModifyVolume",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeInstances",
      "ec2:DescribeSnapshots",
      "ec2:DescribeTags",
      "ec2:DescribeVolumes",
      "ec2:DescribeVolumesModifications",
    ]
  }

  statement {
    sid    = ""
    effect = "Allow"

    resources = [
      "arn:${var.addon_context.aws_partition_id}:ec2:*:*:volume/*",
      "arn:${var.addon_context.aws_partition_id}:ec2:*:*:snapshot/*",
    ]

    actions = ["ec2:CreateTags"]

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"

      values = [
        "CreateVolume",
        "CreateSnapshot",
      ]
    }
  }

  statement {
    sid    = ""
    effect = "Allow"

    resources = [
      "arn:${var.addon_context.aws_partition_id}:ec2:*:*:volume/*",
      "arn:${var.addon_context.aws_partition_id}:ec2:*:*:snapshot/*",
    ]

    actions = ["ec2:DeleteTags"]
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:CreateVolume"]

    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/ebs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:CreateVolume"]

    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/CSIVolumeName"
      values   = ["*"]
    }
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:CreateVolume"]

    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/kubernetes.io/cluster/*"
      values   = ["owned"]
    }
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteVolume"]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/ebs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteVolume"]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/CSIVolumeName"
      values   = ["*"]
    }
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteVolume"]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/kubernetes.io/cluster/*"
      values   = ["owned"]
    }
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteSnapshot"]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/CSIVolumeSnapshotName"
      values   = ["*"]
    }
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteSnapshot"]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/ebs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }
}

resource "aws_iam_policy" "aws_ebs_csi_driver" {
  count = var.enable_amazon_eks_aws_ebs_csi_driver ? 1 : 0

  name        = "${var.eks_cluster_name}-aws-ebs-csi-driver-irsa"
  description = "IAM Policy for AWS EBS CSI Driver"
  path        = null
  policy      = data.aws_iam_policy_document.aws_ebs_csi_driver[0].json

}

module "irsa_addon_amazon_eks_aws_ebs_csi_driver" {
  source = "./addons/irsa"

  count = var.enable_amazon_eks_aws_ebs_csi_driver ? 1 : 0

  create_kubernetes_namespace       = false
  create_kubernetes_service_account = false
  kubernetes_namespace              = "kube-system"
  kubernetes_service_account        = "ebs-csi-controller-sa"
  irsa_iam_policies                 = [aws_iam_policy.aws_ebs_csi_driver[0].arn]
  irsa_iam_role_path                = "/"
  irsa_iam_permissions_boundary     = ""
  eks_cluster_id                    = var.eks_cluster_name
  eks_oidc_provider_arn             = data.aws_eks_cluster.eks.identity[0].oidc[0].issuer
}

resource "aws_eks_addon" "aws_ebs_csi_driver" {
  count                    = var.enable_amazon_eks_aws_ebs_csi_driver  ? 1 : 0
  cluster_name             = var.eks_cluster_name
  addon_name               = "aws-ebs-csi-driver"
  addon_version            = data.aws_eks_addon_version.this.version
  resolve_conflicts        = "OVERWRITE"
  service_account_role_arn = var.enable_amazon_eks_aws_ebs_csi_driver ? module.irsa_addon_amazon_eks_aws_ebs_csi_driver[0].irsa_iam_role_arn : null
  preserve                 = true

}

module "cert_manager" {
  source = "./addons/helm_addon"

  manage_via_gitops = false

  # https://github.com/kubernetes/autoscaler/blob/master/charts/cluster-autoscaler/Chart.yaml
  helm_config = merge({
    name        = "cluster-autoscaler"
    chart       = "cluster-autoscaler"
    version     = "9.21.0"
    repository  = "https://kubernetes.github.io/autoscaler"
    namespace   = "kube-system"
    description = "Cluster AutoScaler helm Chart deployment configuration."
    values = [templatefile("./addons/cluster_autoscaler/cluster_autoscaler.yaml", {
      aws_region     = var.region
      eks_cluster_id = var.cluster_name
      image_tag      = "v${data.aws_eks_cluster.eks.version}.0"
    })]
    }
  )

  set_values = [
    {
      name  = "rbac.serviceAccount.create"
      value = "false"
    },
    {
      name  = "rbac.serviceAccount.name"
      value = "cluster-autoscaler-sa"
    }
  ]

  irsa_config = {
    create_kubernetes_namespace       = false
    kubernetes_namespace              = "kube-system"
    create_kubernetes_service_account = true
    kubernetes_service_account        = "cluster-autoscaler-sa"
    irsa_iam_policies                 = [aws_iam_policy.cluster_autoscaler.arn]
  }

  addon_context = var.addon_context
}

data "aws_iam_policy_document" "cluster_autoscaler" {
  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeTags",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeLaunchTemplateVersions"
    ]
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "autoscaling:SetDesiredCapacity",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
      "ec2:DescribeInstanceTypes",
      "eks:DescribeNodegroup",
    ]

    condition {
      test     = "StringEquals"
      variable = "autoscaling:ResourceTag/k8s.io/cluster-autoscaler/${var.cluster_name}"
      values   = ["owned"]
    }
  }
}

resource "aws_iam_policy" "cluster_autoscaler" {
  name        = "${var.cluster_name}-cluster-autoscaler-irsa"
  description = "Cluster Autoscaler IAM policy"
  policy      = data.aws_iam_policy_document.cluster_autoscaler.json

}

module "k8s_addons" {
  depends_on     = [module.service_monitor_crd]
  source         = "./EKS-Blueprint/modules/kubernetes-addons"
  eks_cluster_id = var.eks_cluster_name

  #ebs csi driver
  enable_amazon_eks_aws_ebs_csi_driver = var.amazon_eks_aws_ebs_csi_driver_enabled
  amazon_eks_aws_ebs_csi_driver_config = {
    additional_iam_policies = [var.kms_policy_arn]
  }

  #cluster-autoscaler
  enable_cluster_autoscaler = var.cluster_autoscaler_enabled
  cluster_autoscaler_helm_config = {
    version = var.cluster_autoscaler_chart_version
    values = [templatefile("${path.module}/addons/cluster_autoscaler/cluster_autoscaler.yaml", {
      aws_region     = data.aws_region.current.name
      eks_cluster_id = var.eks_cluster_name
    })]
  }

  #metrics server
  enable_metrics_server = var.metrics_server_enabled
  metrics_server_helm_config = {
    version = var.metrics_server_helm_version
    values  = [file("${path.module}/addons/metrics_server/metrics_server.yaml")]
  }

  #keda
  enable_keda = var.keda_enabled

  #Ingress Nginx Controller
  enable_ingress_nginx = var.ingress_nginx_enabled
  ingress_nginx_helm_config = {
    version = var.ingress_nginx_version
    values = [
      templatefile("${path.module}/addons/nginx_ingress/nginx_ingress.yaml", {
        enable_service_monitor = var.service_monitor_crd_enabled

      })
    ]
  }

  #Cert Manager
  enable_cert_manager                      = var.cert_manager_enabled
  cert_manager_letsencrypt_email           = var.cert_manager_letsencrypt_email
  cert_manager_install_letsencrypt_issuers = var.cert_manager_install_letsencrypt_r53_issuers
  cert_manager_helm_config = {
    values = [
      file("${path.module}/addons/cert_manager/cert_manager.yaml")
    ]
  }

  #Aws Load balancer Controller
  enable_aws_load_balancer_controller = var.enable_aws_load_balancer_controller
  aws_load_balancer_controller_helm_config = {
    version = var.aws_load_balancer_version
    values = [
      file("${path.module}/addons/aws_alb/aws_alb.yaml")
    ]
  }

  enable_coredns_autoscaler = var.cluster_propotional_autoscaler_enabled
  coredns_autoscaler_helm_config = {
    values = [
      file("${path.module}/addons/cluster_propotional_autoscaler/cpa.yaml")
    ]
  }

  enable_karpenter = var.karpenter_enabled
  karpenter_helm_config = {
    values = [
      templatefile("${path.module}/addons/karpenter/karpenter.yaml", {
        eks_cluster_id            = var.eks_cluster_name,
        node_iam_instance_profile = aws_iam_instance_profile.karpenter_profile.name
        eks_cluster_endpoint      = data.aws_eks_cluster.eks.endpoint
      })
    ]
  }
  karpenter_node_iam_instance_profile = aws_iam_instance_profile.karpenter_profile.name

  enable_reloader = var.reloader_enabled
  reloader_helm_config = {
    values = [
      templatefile("${path.module}/addons/reloader/reloader.yaml", {
        enable_service_monitor = var.service_monitor_crd_enabled
      })
    ]
    namespace        = "kube-system"
    create_namespace = false
  }

  enable_aws_node_termination_handler = var.aws_node_termination_handler_enabled
  aws_node_termination_handler_helm_config = {
    values = [
      templatefile("${path.module}/addons/aws_node_termination_handler/aws_nth.yaml", {
        enable_service_monitor = var.service_monitor_crd_enabled
      })
    ]
  }

  enable_amazon_eks_vpc_cni        = var.amazon_eks_vpc_cni_enabled
  enable_aws_efs_csi_driver        = var.efs_storage_class_enabled
  aws_efs_csi_driver_irsa_policies = [var.kms_policy_arn]
}

resource "helm_release" "cert_manager_le_http" {
  depends_on = [module.k8s_addons]
  count      = var.cert_manager_install_letsencrypt_http_issuers ? 1 : 0
  name       = "cert-manager-le-http"
  chart      = "${path.module}/addons/cert-manager-le-http"
  version    = "0.1.0"
  set {
    name  = "email"
    value = var.cert_manager_letsencrypt_email
    type  = "string"
  }
}

# OPEN: Default label needs to be removed from gp2 storageclass in order to make gp3 as default choice for EBS volume provisioning.
module "single_az_sc" {
  for_each                             = { for sc in var.single_az_sc_config : sc.name => sc }
  source                               = "./addons/aws-ebs-storage-class"
  kms_key_id                           = var.kms_key_arn
  availability_zone                    = each.value.zone
  single_az_ebs_gp3_storage_class      = var.single_az_ebs_gp3_storage_class_enabled
  single_az_ebs_gp3_storage_class_name = each.value.name
}

module "external_secrets" {
  depends_on             = [module.service_monitor_crd]
  source                 = "./addons/external_secrets"
  count                  = var.external_secrets_enabled ? 1 : 0
  name                   = var.name
  region                 = data.aws_region.current.name
  cluster_id             = var.eks_cluster_name
  environment            = var.environment
  provider_url           = data.aws_eks_cluster.eks.identity[0].oidc[0].issuer
  enable_service_monitor = var.service_monitor_crd_enabled
}

### EFS
module "efs" {
  depends_on         = [module.k8s_addons]
  source             = "./addons/efs"
  name               = var.name
  count              = var.efs_storage_class_enabled ? 1 : 0
  vpc_id             = var.vpc_id
  region             = data.aws_region.current.name
  environment        = var.environment
  kms_key_id         = var.kms_key_arn
  private_subnet_ids = data.aws_subnet_ids.private_subnet_ids.ids
}

data "kubernetes_service" "nginx-ingress" {
  depends_on = [module.k8s_addons]
  metadata {
    name      = "ingress-nginx-controller"
    namespace = "ingress-nginx"
  }
}

module "velero" {
  source        = "./addons/velero"
  name          = var.name
  count         = var.velero_enabled ? 1 : 0
  region        = data.aws_region.current.name
  cluster_id    = var.eks_cluster_name
  environment   = var.environment
  velero_config = var.velero_config
}

module "istio" {
  source = "./addons/istio"
  count  = var.istio_enabled ? 1 : 0


}

module "karpenter_provisioner" {
  depends_on                           = [module.k8s_addons]
  source                               = "./addons/karpenter_provisioner"
  count                                = var.karpenter_provisioner_enabled ? 1 : 0
  sg_selector_name                     = var.eks_cluster_name
  subnet_selector_name                 = var.karpenter_provisioner_config.private_subnet_name
  karpenter_ec2_capacity_type          = var.karpenter_provisioner_config.instance_capacity_type
  excluded_karpenter_ec2_instance_type = var.karpenter_provisioner_config.excluded_instance_type
}

resource "kubernetes_namespace" "internal_nginx" {
  count = var.internal_ingress_nginx_enabled ? 1 : 0
  metadata {
    name = "internal-ingress-nginx"
  }
}

resource "helm_release" "internal_nginx" {
  depends_on = [kubernetes_namespace.internal_nginx]
  count      = var.internal_ingress_nginx_enabled ? 1 : 0
  name       = "internal-ingress-nginx"
  chart      = "ingress-nginx"
  version    = "4.1.4"
  namespace  = "internal-ingress-nginx"
  repository = "https://kubernetes.github.io/ingress-nginx"
  values = [
    templatefile("${path.module}/addons/internal_nginx_ingress/ingress.yaml", {
      enable_service_monitor = var.service_monitor_crd_enabled
    })
  ]
}

data "kubernetes_service" "internal-nginx-ingress" {
  depends_on = [helm_release.internal_nginx]
  metadata {
    name      = "internal-ingress-nginx-controller"
    namespace = "internal-ingress-nginx"
  }
}